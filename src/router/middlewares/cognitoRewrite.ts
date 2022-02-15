import { URLSearchParams } from 'url';
import { cleanAuthHeader } from 'fhir-works-on-aws-interface';
import * as _ from 'lodash';
import express from 'express';
import * as axios from 'axios';
import * as jose from 'jose';
import getComponentLogger from '../../loggerBuilder';
import RouteHelper from '../routes/routeHelper';
import AWS from '../../AWS';

const TOKEN_USE_ACCESS = 'ACCESS';
const OKTA_SCOPE = 'system/*.*';
const OKTA_GRANT_TYPE = 'client_credentials';
const SSM_OKTA_TOKEN_URL_NAME = `/${process.env.STAGE}/fhirworks-auth-issuer-endpoint`;
const SSM_OKTA_CLIENT_ID_NAME = `/${process.env.STAGE}/fhirworks-api-client-id`;
const SSM_OKTA_CLIENT_SECRET_NAME = `/${process.env.STAGE}/fhirworks-api-client-secret`;
const OKTA_TOKEN_TTL_BUFFER = 30; // buffer to refresh token before expiration date
const OKTA_PARAMETERS_TTL = 900000; // ttl for SSM okta parameters
let RETRY_SLEEP_BASE = 10; // writable for unit tests
const MSG_NO_AUTH_HEADER = 'no authorization bearer token found';
const MSG_UNABLE_TO_DECODE = 'unable to decode auth token';
const MSG_JWK_URL_NO_MATCH = 'token not from cognito JWK';
const MSG_NO_COGNITO_JWK_KID = 'key id was not found for cognito token';
const MSG_JWT_NOT_VERIFIED = 'unable to verify';
const MSG_NOT_COGNITO_USER = 'Not a valid cognito username or token_use';
const MSG_FATAL_ERROR = 'error processing cognito middleware';
const logger = getComponentLogger().child({ method: 'cognitoRewrite' });
const ssmClient: AWS.SSM = new AWS.SSM();

interface OktaParameters {
    tokenUrl: string;
    clientId: string;
    clientSecret: string;
}
/* eslint-disable camelcase */
interface OktaResponse {
    token_type: string;
    expires_in: number;
    access_token: string;
}
/* eslint-enable camelcase */

/**
 * returns the parameter store values for Okta
 *
 * @return {AWSLambda.SSM.ParameterList} Okta parameter store parameters
 */
let oktaParms: OktaParameters | undefined;
setInterval(() => {
    // flush the okta ssm parameter store params every 15 minutes from boot
    oktaParms = undefined;
}, OKTA_PARAMETERS_TTL);
const getOktaParameters = async (): Promise<OktaParameters> => {
    if (_.isUndefined(oktaParms)) {
        const response = await ssmClient
            .getParameters({
                Names: [SSM_OKTA_TOKEN_URL_NAME, SSM_OKTA_CLIENT_ID_NAME, SSM_OKTA_CLIENT_SECRET_NAME],
                WithDecryption: true,
            })
            .promise();

        const tokenUrl = response.Parameters?.find((p) => {
            return p.Name === SSM_OKTA_TOKEN_URL_NAME;
        })?.Value;
        const clientId = response.Parameters?.find((p) => {
            return p.Name === SSM_OKTA_CLIENT_ID_NAME;
        })?.Value;
        const clientSecret = response.Parameters?.find((p) => {
            return p.Name === SSM_OKTA_CLIENT_SECRET_NAME;
        })?.Value;

        if (_.isUndefined(tokenUrl) || _.isUndefined(clientId) || _.isUndefined(clientSecret)) {
            throw new Error('Invalid okta SSM parameters');
        }

        oktaParms = {
            tokenUrl,
            clientId,
            clientSecret,
        };
    }

    return oktaParms;
};

const keyToPem = new Map<string, jose.KeyLike>();
/**
 * helper method to get a JWK public key in KeyLike format
 * @param {string} kid JWK key ID
 * @param {string} jwkUrl URL to JWK keys
 *
 * @return {jose.KeyLike} JWK public key imported to jose
 */
const getJWK = async (kid: string, jwkUrl: string): Promise<jose.KeyLike | undefined> => {
    if (!keyToPem.has(kid)) {
        let response: axios.AxiosResponse<jose.JSONWebKeySet, any> | undefined;
        const retryBase = RETRY_SLEEP_BASE;

        for (let i = 0; i < 5; i += 1) {
            try {
                /* eslint-disable no-await-in-loop */
                if (i !== 0) {
                    await new Promise((resolve) => setTimeout(resolve, 2 ** (i + retryBase)));
                }
                response = await axios.default.get<jose.JSONWebKeySet>(jwkUrl, {
                    timeout: 60000,
                });
                break;
                /* eslint-enable no-await-in-loop */
            } catch (e) {
                logger.error({ e, url: jwkUrl }, 'Error calling to get JWK public keys');
                if (i === 4) {
                    throw new Error('Unable to get JWK');
                }
            }
        }

        response?.data.keys.forEach(async (key: jose.JWK) => {
            if (!_.isUndefined(key.kid)) {
                const jwk = await jose.importJWK(key);

                // make sure it's a KeyLike and not UInt8
                // @ts-ignore
                if (!_.isUndefined(jwk.type)) {
                    // @ts-ignore
                    keyToPem.set(key.kid, jwk);
                } else {
                    logger.info({ kid: key.kid }, 'JWK imported as uint8array type');
                }
            }
        });
    }

    return keyToPem.get(kid);
};

/**
 * returns the cognito JWK as a PEM for the @parm
 * @param {string} kid Cognito Key ID
 *
 * @return {string} Cognito public key in PEM format
 */
const getCognitoJWK = async (kid: string): Promise<jose.KeyLike | undefined> => {
    return getJWK(kid, `${process.env.COGNITO_JWK_URL}/.well-known/jwks.json`);
};

/**
 * returns the okta JWK as a PEM for the @parm
 * @param {string} kid Okta Key ID
 *
 * @return {string} Okta public key in PEM format
 */
const getOktaJWK = async (kid: string): Promise<jose.KeyLike | undefined> => {
    const oktaParameters = await getOktaParameters();

    return getJWK(kid, `${oktaParameters.tokenUrl}/v1/keys`);
};

const loginToOktaOAuth2 = async (): Promise<OktaResponse> => {
    const oktaParameters = await getOktaParameters();

    // call Okta's OAuth2 w/client credentials
    let response: any;
    const params = new URLSearchParams({
        client_id: oktaParameters.clientId,
        scope: OKTA_SCOPE,
        client_secret: oktaParameters.clientSecret,
        grant_type: OKTA_GRANT_TYPE,
    }).toString();
    for (let i = 0; i < 5; i += 1) {
        try {
            /* eslint-disable no-await-in-loop */
            if (i !== 0) {
                await new Promise((resolve) => {
                    setTimeout(resolve, 2 ** (i + 10));
                });
            }

            response = await axios.default.post<OktaResponse>(oktaParameters.tokenUrl, params, {
                timeout: 60000,
            });
            break;
            /* eslint-enable no-await-in-loop */
        } catch (e) {
            logger.error({ e }, 'Error calling to login to oAuth2');
            if (i === 4) {
                throw new Error('Unable to login to Okta oAuth2');
            }
        }
    }

    return response.data;
};

/**
 * returns the valid Okta oAuth2 accessToken for our canned user
 *
 * @return {string} A good string
 */
let oktaToken: OktaResponse | undefined;
const getOktaToken = async (): Promise<string> => {
    // 1. unprimed
    // 2. good primed token
    // 3. bad primed token

    // check cached token to see if it's valid
    if (_.isUndefined(oktaToken)) {
        // get new token
        oktaToken = await loginToOktaOAuth2();
    } else {
        // check if okta token we gots previously is still valid
        const decodedPayload = jose.decodeJwt(oktaToken.access_token);

        if (!_.isUndefined(decodedPayload.exp) && !_.isUndefined(decodedPayload.iat)) {
            // validate the expiration
            const now = Math.floor(new Date().valueOf() / 1000);
            if (now > decodedPayload.iat || now < decodedPayload.iat - OKTA_TOKEN_TTL_BUFFER) {
                // non expired token

                // check if we want to validate the signature as well
                // this isn't really needed because we call verify or introspection in smart-authz
                // in future middleware. However, have the flag just in case we need to do verify here
                if (
                    process.env.COGNITO_VALIDATE_OKTA_TOKEN !== undefined &&
                    process.env.COGNITO_VALIDATE_OKTA_TOKEN.toLowerCase().trim() === 'true'
                ) {
                    const decodedHeader = jose.decodeProtectedHeader(oktaToken.access_token);
                    if (!_.isUndefined(decodedHeader.kid)) {
                        const oktaJWK = await getOktaJWK(decodedHeader.kid);
                        if (!_.isUndefined(oktaJWK)) {
                            try {
                                await jose.jwtVerify(oktaToken.access_token, oktaJWK, {
                                    issuer: process.env.COGNITO_JWK_URL,
                                    maxTokenAge: oktaToken.expires_in - OKTA_TOKEN_TTL_BUFFER,
                                });

                                // token is too legit to quit
                            } catch (err) {
                                // something is wrong with the token; just rebuild the token
                                oktaToken = await loginToOktaOAuth2();
                            }
                        } else {
                            // sigh, can't find the okta pem
                            logger.error('error getting okta pem. Proceeding with new token');
                            oktaToken = await loginToOktaOAuth2();
                        }
                    } else {
                        logger.debug('existing okta token has no kid. refreshing...');
                        oktaToken = await loginToOktaOAuth2();
                    }
                }
            } else {
                logger.debug('expired okta token. refreshing...');
                oktaToken = await loginToOktaOAuth2();
            }
        } else {
            // just rebuild the whole token
            logger.debug('not able to decode okta token. refreshing...');
            oktaToken = await loginToOktaOAuth2();
        }
    }

    // return the token
    return oktaToken.access_token;
};

/**
 * verifies a cognito JWT and then rewrites the token as an Okta client for SMART authz
 *
 * @returns Async middleware function
 */
export const cognitoRewriteMiddleware: () => (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
) => void = () => {
    return RouteHelper.wrapAsync(async (req: express.Request, res: express.Response, next: express.NextFunction) => {
        try {
            // check if we have an authorization header w/Bearer
            if (
                _.isUndefined(req.headers.authorization) ||
                req.headers.authorization.length < 8 ||
                !req.headers.authorization.startsWith('Bearer')
            ) {
                logger.debug(MSG_NO_AUTH_HEADER);
                next();
            } else {
                const bearerToken = cleanAuthHeader(req.headers.authorization);
                // do a 1st pass parse to see if it's a token from cognito
                const decodedPayload = jose.decodeJwt(bearerToken);

                // see if the token is from cognito
                if (decodedPayload.iss === process.env.COGNITO_JWK_URL) {
                    const decodedHeader = jose.decodeProtectedHeader(bearerToken);

                    if (!_.isUndefined(decodedHeader.kid)) {
                        // it's looks like a token from cognito but we need to verify the token's key with the public key
                        const cognitoJWK: jose.KeyLike | undefined = await getCognitoJWK(decodedHeader.kid);
                        if (!_.isUndefined(cognitoJWK)) {
                            // verify the cognito JWT
                            try {
                                const claim = await jose.jwtVerify(bearerToken, cognitoJWK, {
                                    issuer: process.env.COGNITO_JWK_URL,
                                });

                                // check the use of the token
                                if (
                                    claim.payload.username === process.env.COGNITO_USERNAME &&
                                    claim.payload.token_use === TOKEN_USE_ACCESS
                                ) {
                                    // rewrite to a canned Okta client credentials JWT
                                    const rewriteToken = await getOktaToken();
                                    req.headers.authorization = `Bearer ${rewriteToken}`;
                                    next();
                                } else {
                                    // it's a valid JWT from our configure cognito
                                    // however, it's either not the airview user
                                    // or someone is passing in a different oAuth2 token
                                    logger.debug(MSG_NOT_COGNITO_USER);
                                    res.status(403).send();
                                }
                            } catch (err) {
                                logger.info({ err }, MSG_JWT_NOT_VERIFIED);
                                res.status(403).send();
                            }
                        } else {
                            logger.error(MSG_NO_COGNITO_JWK_KID);
                            res.status(500).send();
                        }
                    } else {
                        logger.debug(MSG_UNABLE_TO_DECODE);
                        next();
                    }
                } else {
                    logger.debug(MSG_JWK_URL_NO_MATCH);
                    next();
                }
            }
        } catch (err) {
            logger.error({ err }, MSG_FATAL_ERROR);
            res.status(500).send();
        }
    });
};

// test hook helper function to set the ret
export function setRetrySleepBase(base: number) {
    RETRY_SLEEP_BASE = base;
}
