/* ugh, jest is something something
 * https://github.com/panva/jose/issues/307
 * https://github.com/jsdom/jsdom/issues/2524#issuecomment-897707183
 */
/* eslint-disable import/newline-after-import,import/order,import/first  */
const { TextEncoder, TextDecoder } = require('util');
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
/* eslint-enable import/newline-after-import,import/order */

import express from 'express';
import * as _ from 'lodash';
import * as jose from 'jose';
import axios from 'axios';
import * as jsonwebtoken from 'jsonwebtoken';
import AWS from 'aws-sdk';
import * as AWSMock from 'aws-sdk-mock';
import { GetParameterRequest } from 'aws-sdk/clients/ssm';
import AWSXRay from 'aws-xray-sdk';
// import rewire from 'rewire';
/* eslint-enable import/first */

jest.mock('axios');
AWSMock.setSDKInstance(AWS);
AWSXRay.setContextMissingStrategy("LOG_ERROR");
process.env.AWS_XRAY_LOG_LEVEL = 'silent';
const stage = 'ci';
process.env.STAGE = stage;
import * as cognitoRewrite from './cognitoRewrite';

describe('cognitoRewrite', () => {
    const cognitoJWKUrl = 'https://cognitojwk.example.com';
    const cognitoKid = 'cognito_jwk_kid';
    const cognitoUserName = 'my_cool_username';
    const oktaJWKUrl = 'https://oktajwk.example.com';
    const oktaKid = 'okta_jwk_kid';
    const oktaIssuerUrl = 'https://oktaissuer.example.com';
    const oktaClientId = 'okta_client_id';
    const oktaClientSecret = 'okta_client_secret';
    let cognitoKeys: any;
    let oktaKeys: any;

    beforeAll(async () => {
        // generate cognito keys
        cognitoKeys = await jose.generateKeyPair('RS256');
        cognitoKeys.privateKeyPEM = await jose.exportPKCS8(cognitoKeys.privateKey);
        cognitoKeys.publicKeyJWK = await jose.exportJWK(cognitoKeys.publicKey);

        // generate oktaKey
        oktaKeys = await jose.generateKeyPair('RS256');
        oktaKeys.privateKeyPEM = await jose.exportPKCS8(oktaKeys.privateKey);
        oktaKeys.publicKeyJWK = await jose.exportJWK(oktaKeys.publicKey);
    });

    beforeEach(async () => {
        // set the env vars
        process.env.COGNITO_REWRITE_ENABLED = 'true';
        process.env.COGNITO_JWK_URL = cognitoJWKUrl;
        process.env.COGNITO_USERNAME = cognitoUserName;
        process.env.STAGE = stage;
        process.env.COGNITO_VALIDATE_OKTA_TOKEN = 'true';

        // stub the I/O
        // @ts-ignore
        axios.get.mockImplementation((url) => {
            switch (url) {
                case `${cognitoJWKUrl}/.well-known/jwks.json`:
                    return Promise.resolve({
                        data: {
                            keys: [_.defaults(cognitoKeys.publicKeyJWK, { kid: cognitoKid, alg: 'RS256' })],
                        },
                    });
                case `${oktaJWKUrl}/v1/keys}`:
                    return Promise.resolve({
                        data: {
                            keys: [_.defaults(oktaKeys.publicKeyJWK, { kid: oktaKid, alg: 'RS256' })],
                        },
                    });
                default:
                    return Promise.reject(new Error('not found'));
            }
        });

        // okta token
        const accessToken = jsonwebtoken.sign({}, oktaKeys.privateKeyPEM, {
            algorithm: 'RS256',
            issuer: oktaJWKUrl,
            keyid: oktaKid,
            expiresIn: 3600,
        });
        // @ts-ignore
        axios.post.mockResolvedValue({
            data: {
                token_type: 'Bearer',
                expires_in: 3600,
                access_token: accessToken,
            }
        });

        // SSM 
        AWSMock.mock('SSM', 'getParameters', (params: GetParameterRequest, callback: Function)=>{
            callback(null, { Parameters: [
                { Name: `/${stage}/fhirworks-auth-issuer-endpoint`, Type:'String', Value:oktaIssuerUrl },
                { Name: `/${stage}/fhirworks-api-client-id`, Type:'String', Value:oktaClientId },
                { Name: `/${stage}/fhirworks-api-client-secret`, Type:'SecureString', Value:oktaClientSecret }
            ]});
        });
    });

     afterEach(() => {
        // clear any env vars
        delete process.env.COGNITO_REWRITE_ENABLED;
        delete process.env.COGNITO_JWK_URL;
        delete process.env.COGNITO_USERNAME;
        delete process.env.STAGE;
        delete process.env.COGNITO_VALIDATE_OKTA_TOKEN;

        // restore any test hook setup
        jest.restoreAllMocks();
        AWSMock.restore();
    });

    describe('middleware', () => {
        let nextStub: jest.Mock;
        let statusStub: jest.Mock;
        let sendStub: jest.Mock;
        beforeEach(() => {
            // express interactions
            nextStub = jest.fn();
            statusStub = jest.fn();
            sendStub = jest.fn();
            statusStub.mockReturnValue({ send: sendStub });
        });

        test('no auth header calls next', (done) => {
            const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());
            const req = { headers: {} } as unknown as express.Request;
            const res = { status: statusStub } as unknown as express.Response;
            fx(req, res, (err: any) => {
                expect(err).toBeUndefined();

                expect(statusStub).not.toBeCalled();
                expect(axios.get).not.toBeCalled();
                expect(axios.post).not.toBeCalled();

                done();
            });
        });

        test('auth header empty calls next', (done) => {
            const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());
            const req = { headers: { authorization: '' } } as unknown as express.Request;
            const res = { status: statusStub } as unknown as express.Response;
            fx(req, res, (err: any) => {
                expect(err).toBeUndefined();

                expect(statusStub).not.toBeCalled();
                expect(axios.get).not.toBeCalled();
                expect(axios.post).not.toBeCalled();

                done();
            });
        });

        test('invalid JWT calls next', (done) => {
            const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());
            const req = { headers: { authorization: 'fubar' } } as unknown as express.Request;
            const res = { status: statusStub } as unknown as express.Response;
            fx(req, res, (err: any) => {
                expect(err).toBeUndefined();

                expect(statusStub).not.toBeCalled();
                expect(axios.get).not.toBeCalled();
                expect(axios.post).not.toBeCalled();

                done();
            });
        });

        test('not cognito JWK URL calls next', (done) => {
            const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());

            const jwt = jsonwebtoken.sign(
                {
                    username: cognitoUserName,
                    token_use: 'ACCESS',
                },
                cognitoKeys.privateKeyPEM,
                {
                    algorithm: 'RS256',
                    issuer: 'https://fubar.example.com',
                    keyid: cognitoKid,
                    expiresIn: 3600,
                },
            );
            const req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
            const res = { status: statusStub } as unknown as express.Response;
            fx(req, res, (err: any) => {
                expect(err).toBeUndefined();

                expect(statusStub).not.toBeCalled();
                expect(axios.get).not.toBeCalled();
                expect(axios.post).not.toBeCalled();

                done();
            });
        });

        it('cognito JWK URL not 200 sends 500', (done) => {
            const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());

            // redefine the axios.get call to return 500
            // @ts-ignore
            axios.get.mockReset();
            // @ts-ignore
            axios.get.mockRejectedValue(new Error('not 200'));

            cognitoRewrite.setRetrySleepBase(-10);

            const jwt = jsonwebtoken.sign(
                {
                    username: cognitoUserName,
                    token_use: 'ACCESS',
                },
                cognitoKeys.privateKeyPEM,
                {
                    algorithm: 'RS256',
                    issuer: cognitoJWKUrl,
                    keyid: cognitoKid,
                    expiresIn: 3600,
                },
            );

            const req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
            const res = {
                status: (code: number) => {
                    return {
                        send: () => {
                            expect(nextStub).not.toBeCalled();
                            expect(code).toBe(500);
                            expect(axios.get).toBeCalled();
                            // @ts-ignore
                            expect(axios.get.mock.calls[0][0]).toEqual(`${cognitoJWKUrl}/.well-known/jwks.json`);
                            expect(axios.post).not.toBeCalled();

                            done();
                        },
                    };
                },
            } as unknown as express.Response;

            fx(req, res, nextStub);
        });

        test('cognito kid not in JWK calls next', (done) => {
            const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());

            const jwt = jsonwebtoken.sign(
                {
                    username: cognitoUserName,
                    token_use: 'ACCESS',
                },
                cognitoKeys.privateKeyPEM,
                {
                    algorithm: 'RS256',
                    issuer: cognitoJWKUrl,
                    keyid: 'fubar_kid',
                    expiresIn: 3600,
                },
            );

            const req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
            const res = {
                status: (code: number) => {
                    return {
                        send: () => {
                            expect(nextStub).not.toBeCalled();
                            expect(code).toBe(500);
                            expect(axios.get).toBeCalled();
                            // @ts-ignore
                            expect(axios.get.mock.calls[0][0]).toEqual(`${cognitoJWKUrl}/.well-known/jwks.json`);
                            expect(axios.post).not.toBeCalled();

                            done();
                        },
                    };
                },
            } as unknown as express.Response;

            fx(req, res, nextStub);
        });

        test('cognito token expired sends 403', (done) => {
            const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());

            const jwt = jsonwebtoken.sign(
                {
                    username: cognitoUserName,
                    token_use: 'ACCESS',
                },
                cognitoKeys.privateKeyPEM,
                {
                    algorithm: 'RS256',
                    issuer: cognitoJWKUrl,
                    keyid: cognitoKid,
                    expiresIn: -1000,
                },
            );

            const req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
            const res = {
                status: (code: number) => {
                    return {
                        send: () => {
                            expect(nextStub).not.toBeCalled();
                            expect(code).toBe(403);
                            expect(axios.get).toBeCalled();
                            // @ts-ignore
                            expect(axios.get.mock.calls[0][0]).toEqual(`${cognitoJWKUrl}/.well-known/jwks.json`);
                            expect(axios.post).not.toBeCalled();

                            done();
                        },
                    };
                },
            } as unknown as express.Response;

            fx(req, res, nextStub);
        });

        test('username not cognito username sends 403', (done) => {
            const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());

            const jwt = jsonwebtoken.sign(
                {
                    username: 'fubar_username',
                    token_use: 'ACCESS',
                },
                cognitoKeys.privateKeyPEM,
                {
                    algorithm: 'RS256',
                    issuer: cognitoJWKUrl,
                    keyid: cognitoKid,
                    expiresIn: 3600,
                },
            );

            const req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
            const res = {
                status: (code: number) => {
                    return {
                        send: () => {
                            expect(nextStub).not.toBeCalled();
                            expect(code).toBe(403);
                            expect(axios.get).toBeCalled();
                            // @ts-ignore
                            expect(axios.get.mock.calls[0][0]).toEqual(`${cognitoJWKUrl}/.well-known/jwks.json`);
                            expect(axios.post).not.toBeCalled();

                            done();
                        },
                    };
                },
            } as unknown as express.Response;

            fx(req, res, nextStub);
        });

        test('token_use not ACCESS sends 403', (done) => {
            const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());

            const jwt = jsonwebtoken.sign(
                {
                    username: cognitoUserName,
                    token_use: 'fubar',
                },
                cognitoKeys.privateKeyPEM,
                {
                    algorithm: 'RS256',
                    issuer: cognitoJWKUrl,
                    keyid: cognitoKid,
                    expiresIn: 3600,
                },
            );

            const req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
            const res = {
                status: (code: number) => {
                    return {
                        send: () => {
                            expect(nextStub).not.toBeCalled();
                            expect(code).toBe(403);
                            expect(axios.get).toBeCalled();
                            // @ts-ignore
                            expect(axios.get.mock.calls[0][0]).toEqual(`${cognitoJWKUrl}/.well-known/jwks.json`);
                            expect(axios.post).not.toBeCalled();

                            done();
                        },
                    };
                },
            } as unknown as express.Response;

            fx(req, res, nextStub);
        });

        test('valid cognito token rewritten', (done) => {
            const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());

            const jwt = jsonwebtoken.sign(
                {
                    username: cognitoUserName,
                    token_use: 'ACCESS',
                },
                cognitoKeys.privateKeyPEM,
                {
                    algorithm: 'RS256',
                    issuer: cognitoJWKUrl,
                    keyid: cognitoKid,
                    expiresIn: 3600,
                },
            );

            const req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
            const res = { status: statusStub } as unknown as express.Response;

            fx(req, res, (err: any)=>{
                expect(err).toBeUndefined();

                expect(statusStub).not.toBeCalled();
                expect(req.headers.authorization).not.toBeUndefined();
                expect(req.headers.authorization).not.toEqual(`Bearer ${jwt}`);

                done();
            });
        });
    });

    // describe('getOktaParameters', () => {});

    // describe('getPem', () => {});

    // describe('loginToOktaOAuth2', () => {});

    // describe('getOktaToken', () => {});
});
