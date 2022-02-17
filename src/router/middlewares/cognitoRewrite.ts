import { URLSearchParams } from 'url';
import { cleanAuthHeader } from 'fhir-works-on-aws-interface';
import * as _ from 'lodash';
import express from 'express';
import * as axios from 'axios';
import * as jose from 'jose';
import AWS from 'aws-sdk';
import getComponentLogger from '../../loggerBuilder';
import RouteHelper from '../routes/routeHelper';

const TOKEN_USE_ACCESS = 'access';
const OKTA_SCOPE = 'system/*.*';
const OKTA_GRANT_TYPE = 'client_credentials';
const SSM_OKTA_TOKEN_URL_NAME = `/${process.env.STAGE}/fhirworks-auth-issuer-endpoint`;
const SSM_OKTA_CLIENT_ID_NAME = `/${process.env.STAGE}/fhirworks-api-client-id`;
const SSM_OKTA_CLIENT_SECRET_NAME = `/${process.env.STAGE}/fhirworks-api-client-secret`;
const OKTA_EXP_TTL_BUFFER = 300; // buffer to refresh token before expiration date in seconds
const OKTA_IAT_BUFFER = 15; // buffer to handle clock skew between signer & this node in seconds
const CACHE_TTL = 900000; // ttl for SSM okta parameters
let RETRY_SLEEP_BASE = 10; // writable for unit tests
const MSG_NO_AUTH_HEADER = 'no authorization bearer token found';
const MSG_UNABLE_TO_DECODE = 'unable to decode auth token';
const MSG_JWK_URL_NO_MATCH = 'token not from cognito JWK';
const MSG_NO_COGNITO_JWK_KID = 'key id was not found for cognito token';
const MSG_JWT_NOT_VERIFIED = 'unable to verify';
const MSG_NOT_COGNITO_USER = 'Not a valid cognito username or token_use';
const MSG_NO_OKTA_TOKEN = 'error getting okta token';
const MSG_CANT_GET_OKTA_PEM = 'error getting okta pem. Proceeding with new token';
const MSG_OKTA_TOKEN_NO_KID = 'existing okta token has no kid. refreshing...';
const MSG_OKTA_TOKEN_EXPIRED = 'expired okta token. refreshing...';
const MSG_OKTA_UNABLE_TO_DECODE = 'not able to decode okta token. refreshing...';
const MSG_OKTA_INVALID_TOKEN = 'invalid okta token refreshing...';

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

const logger = getComponentLogger().child({ method: 'cognitoRewrite' });
const keyToPem = new Map<string, jose.KeyLike>();
let oktaParms: OktaParameters | undefined;
let ssmClient: AWS.SSM;
let oktaToken: OktaResponse | undefined;

// // flush the various caches periodically
setInterval(() => {
    oktaParms = undefined;
    keyToPem.clear();
}, CACHE_TTL);

/**
 * returns the parameter store values for Okta
 *
 * @return {AWSLambda.SSM.ParameterList} Okta parameter store parameters
 */
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
                    response = undefined;
                    break;
                }
            }
        }

        if (!_.isUndefined(response)) {
            for (let i = 0; i < response.data.keys.length; i += 1) {
                const key = response.data.keys[i];
                if (!_.isUndefined(key.kid)) {
                    /* eslint-disable no-await-in-loop */
                    const jwk = await jose.importJWK(key);
                    /* eslint-enable no-await-in-loop */

                    // make sure it's a KeyLike and not UInt8
                    // @ts-ignore
                    if (!_.isUndefined(jwk.type)) {
                        // @ts-ignore
                        keyToPem.set(key.kid, jwk);
                    } else {
                        logger.info({ kid: key.kid }, 'JWK imported as uint8array type');
                    }
                }
            }
        }
    }

    return keyToPem.get(kid);
};

/**
 * returns the cognito JWK as a PEM for the kid
 * @param {string} kid Cognito Key ID
 *
 * @return {string} Cognito public key in PEM format
 */
const getCognitoJWK = async (kid: string): Promise<jose.KeyLike | undefined> => {
    return getJWK(kid, `${process.env.COGNITO_JWK_URL}/.well-known/jwks.json`);
};

/**
 * returns the okta JWK as a PEM for the kid
 * @param {string} kid Okta Key ID
 *
 * @return {string} Okta public key in PEM format
 */
const getOktaJWK = async (kid: string): Promise<jose.KeyLike | undefined> => {
    const oktaParameters = await getOktaParameters();

    return getJWK(kid, `${oktaParameters.tokenUrl}/v1/keys`);
};

/**
 * Logins in to okta with the configured client credentials
 *
 * @return {string} Okta public key in PEM format
 */
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
    const retryBase = RETRY_SLEEP_BASE;
    for (let i = 0; i < 5; i += 1) {
        try {
            /* eslint-disable no-await-in-loop */
            if (i !== 0) {
                await new Promise((resolve) => setTimeout(resolve, 2 ** (i + retryBase)));
            }

            response = await axios.default.post<OktaResponse>(`${oktaParameters.tokenUrl}/token`, params, {
                timeout: 60000,
            });
            break;
            /* eslint-enable no-await-in-loop */
        } catch (e) {
            logger.error({ e }, 'Error calling to login to oAuth2');
            if (i === 4) {
                throw new Error('unable to login to okta');
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
        let decodedPayload: jose.JWTPayload | undefined;
        let decoded = false;
        try {
            decodedPayload = jose.decodeJwt(oktaToken.access_token);
            decoded = true;
        } catch (err) {
            logger.error({ err }, MSG_OKTA_UNABLE_TO_DECODE);
        }

        if (
            decoded &&
            !_.isUndefined(decodedPayload) &&
            !_.isUndefined(decodedPayload.exp) &&
            !_.isUndefined(decodedPayload.iat)
        ) {
            // validate the expiration
            const now = Math.floor(new Date().valueOf() / 1000);
            if (now > decodedPayload.iat - OKTA_IAT_BUFFER && now < decodedPayload.exp - OKTA_EXP_TTL_BUFFER) {
                // non expired token

                // check if we want to validate the signature as well
                // this isn't really needed because we call verify or introspection in smart-authz
                // in future middleware. However, have the flag just in case we need to do verify here
                if (
                    process.env.COGNITO_VALIDATE_OKTA_TOKEN !== undefined &&
                    process.env.COGNITO_VALIDATE_OKTA_TOKEN.toLowerCase().trim() === 'true'
                ) {
                    decoded = false;
                    let decodedHeader: jose.ProtectedHeaderParameters | undefined;
                    try {
                        decodedHeader = jose.decodeProtectedHeader(oktaToken.access_token);
                        decoded = true;
                    } catch (err) {
                        logger.error({ err }, MSG_OKTA_UNABLE_TO_DECODE);
                    }

                    if (decoded && !_.isUndefined(decodedHeader) && !_.isUndefined(decodedHeader.kid)) {
                        // get the okta JWK
                        const oktaJWK = await getOktaJWK(decodedHeader.kid);
                        if (!_.isUndefined(oktaJWK)) {
                            const oktaParameters = await getOktaParameters();
                            try {
                                await jose.jwtVerify(oktaToken.access_token, oktaJWK, {
                                    issuer: oktaParameters.tokenUrl,
                                    maxTokenAge: oktaToken.expires_in - OKTA_EXP_TTL_BUFFER,
                                });

                                // token is too legit to quit
                            } catch (err) {
                                // something is wrong with the token; just rebuild the token
                                logger.error({ err }, MSG_OKTA_INVALID_TOKEN);
                                oktaToken = await loginToOktaOAuth2();
                            }
                        } else {
                            // sigh, can't find the okta pem
                            logger.error(MSG_CANT_GET_OKTA_PEM);
                            oktaToken = await loginToOktaOAuth2();
                        }
                    } else {
                        logger.debug(MSG_OKTA_TOKEN_NO_KID);
                        oktaToken = await loginToOktaOAuth2();
                    }
                }
            } else {
                logger.debug(MSG_OKTA_TOKEN_EXPIRED);
                oktaToken = await loginToOktaOAuth2();
            }
        } else {
            // just rebuild the whole token
            logger.debug(MSG_OKTA_UNABLE_TO_DECODE);
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
export const cognitoRewriteMiddleware: (
    ssm: AWS.SSM,
) => (req: express.Request, res: express.Response, next: express.NextFunction) => void = (ssm: AWS.SSM) => {
    ssmClient = ssm;
    return RouteHelper.wrapAsync(async (req: express.Request, res: express.Response, next: express.NextFunction) => {
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

            let decoded = false;
            let decodedPayload: jose.JWTPayload | undefined;
            try {
                // do a 1st pass parse to see if it's a token from cognito
                decodedPayload = jose.decodeJwt(bearerToken);
                decoded = true;
            } catch (err) {
                logger.error({ err }, MSG_UNABLE_TO_DECODE);
            }

            // see if the token is from cognito
            if (decoded && !_.isUndefined(decodedPayload) && decodedPayload.iss === process.env.COGNITO_JWK_URL) {
                decoded = false;
                let decodedHeader: jose.ProtectedHeaderParameters | undefined;
                try {
                    decodedHeader = jose.decodeProtectedHeader(bearerToken);
                    decoded = true;
                } catch (err) {
                    logger.error({ err }, MSG_UNABLE_TO_DECODE);
                }

                if (decoded && !_.isUndefined(decodedHeader) && !_.isUndefined(decodedHeader.kid)) {
                    // it's looks like a token from cognito but we need to verify the token's key with the public key
                    const cognitoJWK: jose.KeyLike | undefined = await getCognitoJWK(decodedHeader.kid);
                    if (!_.isUndefined(cognitoJWK)) {
                        // verify the cognito JWT
                        let claim: jose.JWTVerifyResult | undefined;
                        let verified: boolean = false;
                        try {
                            claim = await jose.jwtVerify(bearerToken, cognitoJWK, {
                                issuer: process.env.COGNITO_JWK_URL,
                            });
                            verified = true;
                        } catch (err) {
                            logger.info({ err }, MSG_JWT_NOT_VERIFIED);
                        }

                        // really hate the throwing control flow from the crypto libs
                        if (verified && !_.isUndefined(claim) && !_.isUndefined(claim.payload.token_use)) {

                            // check the use of the token
                            if (
                                claim.payload.username === process.env.COGNITO_USERNAME &&
                                (claim.payload.token_use as string).toLowerCase() === TOKEN_USE_ACCESS
                            ) {
                                // rewrite to an impersonated Okta client credentials JWT
                                // try/catch standalone so we don't catch res.status().send() | next() errors
                                let rewriteToken;
                                let gotToken = false;
                                try {
                                    rewriteToken = await getOktaToken();
                                    gotToken = true;
                                } catch (err) {
                                    logger.error({ err }, MSG_NO_OKTA_TOKEN);
                                }
                                if (gotToken && !_.isUndefined(rewriteToken)) {
                                    req.headers.authorization = `Bearer ${rewriteToken}`;
                                    next();
                                } else {
                                    res.status(500).send();
                                }
                            } else {
                                // it's a valid JWT from our configure cognito
                                // however, it's either not the airview user
                                // or someone is passing in a different oAuth2 token
                                logger.debug(MSG_NOT_COGNITO_USER);
                                res.status(403).send();
                            }
                        } else {
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
    });
};

// test hook helper function to set the ret
export function setRetrySleepBase(base: number) {
    RETRY_SLEEP_BASE = base;
}

// test hook helper function for clearing all internal state
export function clear() {
    oktaParms = undefined;
    keyToPem.clear();
    oktaToken = undefined;
}
