/* ugh, jest is something something
 * https://github.com/panva/jose/issues/307
 * https://github.com/jsdom/jsdom/issues/2524#issuecomment-897707183
 * https://github.com/axios/axios/issues/1180#issuecomment-477920274
 */
/* eslint-disable import/newline-after-import,import/order,import/first  */
const { TextEncoder, TextDecoder } = require('util');
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
// @ts-ignore
global.XMLHttpRequest = undefined;
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

jest.mock('axios');
AWS.config.httpOptions = {
    connectTimeout: 0,
    timeout: 0,
};
AWS.config.retryDelayOptions = {
    base: 0,
};
AWSMock.setSDKInstance(AWS);
AWSXRay.setContextMissingStrategy('LOG_ERROR');
process.env.AWS_XRAY_LOG_LEVEL = 'silent';
const stage = 'dev';
process.env.STAGE = stage;
const apiUrl = 'https://apigateway.example.com/dev';
process.env.API_URL = apiUrl;
import * as cognitoRewrite from './cognitoRewrite';
/* eslint-enable import/first */

describe('cognitoRewrite', () => {
    const cognitoJWKUrl = 'https://cognitojwk.example.com';
    const cognitoKid = 'cognito_jwk_kid';
    const cognitoUserName = 'my_cool_username';
    const oktaKid = 'okta_jwk_kid';
    const oktaIssuerUrl = 'https://oktaissuer.example.com';
    const oktaClientId = 'okta_client_id';
    const oktaClientSecret = 'okta_client_secret';
    let cognitoKeys: any;
    let oktaKeys: any;
    let nextStub: jest.Mock;
    let statusStub: jest.Mock;
    let sendStub: jest.Mock;

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

        // reset the state of cognitoRewrite each test
        // also set timeouts to as low as possible
        cognitoRewrite.setRetrySleepBase(-10);
        cognitoRewrite.clear();

        // stub the I/O
        // express interactions
        nextStub = jest.fn();
        statusStub = jest.fn();
        sendStub = jest.fn();
        statusStub.mockReturnValue({ send: sendStub });
        // @ts-ignore
        axios.get.mockImplementation((url) => {
            switch (url) {
                case `${cognitoJWKUrl}/.well-known/jwks.json`:
                    return Promise.resolve({
                        data: {
                            keys: [_.defaults(cognitoKeys.publicKeyJWK, { kid: cognitoKid, alg: 'RS256' })],
                        },
                    });
                case `${oktaIssuerUrl}/v1/keys`:
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
            issuer: oktaIssuerUrl,
            keyid: oktaKid,
            expiresIn: 3600,
            audience: apiUrl,
        });
        // @ts-ignore
        axios.post.mockResolvedValue({
            data: {
                token_type: 'Bearer',
                expires_in: 3600,
                access_token: accessToken,
            },
        });

        // SSM
        AWSMock.mock('SSM', 'getParameters', (params: GetParameterRequest, callback: Function) => {
            callback(null, {
                Parameters: [
                    { Name: `/${stage}/fhirworks-auth-issuer-endpoint`, Type: 'String', Value: oktaIssuerUrl },
                    { Name: `/${stage}/fhirworks-api-client-id`, Type: 'String', Value: oktaClientId },
                    { Name: `/${stage}/fhirworks-api-client-secret`, Type: 'SecureString', Value: oktaClientSecret },
                ],
            });
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
        // @ts-ignore
        axios.get.mockRestore();
        // @ts-ignore
        axios.post.mockRestore();
        AWSMock.restore();
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

        fx(req, res, (err: any) => {
            expect(err).toBeUndefined();

            expect(statusStub).not.toBeCalled();
            expect(req.headers.authorization).not.toBeUndefined();
            expect(req.headers.authorization).not.toEqual(`Bearer ${jwt}`);

            done();
        });
    });

    test('SSM not 200 sends 500', (done) => {
        // update the AWS SSM mock to fail instead of succeed
        AWSMock.restore('SSM', 'getParameters');
        AWSMock.mock('SSM', 'getParameters', (params: GetParameterRequest, callback: Function) => {
            callback(new Error('not 200'));
        });

        const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM({}));

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
                        expect(axios.get.mock.calls.length).toEqual(1);
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

    test('SSM missing parameters sends 500', (done) => {
        // update the AWS SSM mock to return only some of the Parameters
        AWSMock.restore('SSM', 'getParameters');
        AWSMock.mock('SSM', 'getParameters', (params: GetParameterRequest, callback: Function) => {
            callback(null, {
                Parameters: [
                    { Name: `/${stage}/fhirworks-auth-issuer-endpoint`, Type: 'String', Value: oktaIssuerUrl },
                    { Name: `/${stage}/fhirworks-api-client-id`, Type: 'String', Value: oktaClientId },
                ],
            });
        });

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
        const res = {
            status: (code: number) => {
                return {
                    send: () => {
                        expect(nextStub).not.toBeCalled();
                        expect(code).toBe(500);

                        expect(axios.get).toBeCalled();

                        // @ts-ignore
                        expect(axios.get.mock.calls.length).toEqual(1);
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

    test('Okta call not 200 sends 500', (done) => {
        const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());

        // redefine the axios.post call to return 500
        // @ts-ignore
        axios.post.mockReset();
        // @ts-ignore
        axios.post.mockRejectedValue(new Error('not 200'));

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
                        expect(axios.post).toBeCalled();

                        done();
                    },
                };
            },
        } as unknown as express.Response;

        fx(req, res, nextStub);
    });

    test('decoding cached okta token fails rebuilds', (done) => {
        const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());

        // redefine the axios.post call to return a non-decodable access_token
        // @ts-ignore
        axios.post.mockReset();
        // @ts-ignore
        axios.post.mockResolvedValueOnce({
            data: {
                token_type: 'Bearer',
                expires_in: 3600,
                access_token: 'fubar',
            },
        });
        // okta token
        const accessToken = jsonwebtoken.sign({}, oktaKeys.privateKeyPEM, {
            algorithm: 'RS256',
            issuer: oktaIssuerUrl,
            keyid: oktaKid,
            expiresIn: 3600,
            audience: apiUrl,
        });
        // @ts-ignore
        axios.post.mockResolvedValueOnce({
            data: {
                token_type: 'Bearer',
                expires_in: 3600,
                access_token: accessToken,
            },
        });

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

        let req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
        let res = { status: statusStub } as unknown as express.Response;

        fx(req, res, (err: any) => {
            expect(err).toBeUndefined();

            // we only decode on subsequent cached calls
            req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
            res = { status: statusStub } as unknown as express.Response;
            fx(req, res, (err2: any) => {
                expect(err2).toBeUndefined();

                expect(statusStub).not.toBeCalled();
                expect(req.headers.authorization).toEqual(`Bearer ${accessToken}`);

                done();
            });
        });
    });

    test('expired okta token rebuilds', (done) => {
        const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());

        // redefine the axios.post call to return expired and then valid
        // @ts-ignore
        axios.post.mockReset();
        // okta token
        const expiredAccessToken = jsonwebtoken.sign({}, oktaKeys.privateKeyPEM, {
            algorithm: 'RS256',
            issuer: oktaIssuerUrl,
            keyid: oktaKid,
            expiresIn: -3600,
            audience: apiUrl,
        });
        // @ts-ignore
        axios.post.mockResolvedValueOnce({
            data: {
                token_type: 'Bearer',
                expires_in: 3600,
                access_token: expiredAccessToken,
            },
        });
        // okta token
        const accessToken = jsonwebtoken.sign({}, oktaKeys.privateKeyPEM, {
            algorithm: 'RS256',
            issuer: oktaIssuerUrl,
            keyid: oktaKid,
            expiresIn: -3600,
        });
        // @ts-ignore
        axios.post.mockResolvedValueOnce({
            data: {
                token_type: 'Bearer',
                expires_in: 3600,
                access_token: accessToken,
            },
        });

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

        let req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
        let res = { status: statusStub } as unknown as express.Response;

        fx(req, res, (err: any) => {
            expect(err).toBeUndefined();

            // we only decode on subsequent cached calls
            req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
            res = { status: statusStub } as unknown as express.Response;
            fx(req, res, (err2: any) => {
                expect(err2).toBeUndefined();

                expect(statusStub).not.toBeCalled();
                expect(req.headers.authorization).toEqual(`Bearer ${accessToken}`);

                done();
            });
        });
    });

    test('invalid token rebuilds', (done) => {
        const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());

        // redefine the axios.post call to return invalid and then valid
        // @ts-ignore
        axios.post.mockReset();
        // okta token
        const invalidAccessToken = jsonwebtoken.sign({}, oktaKeys.privateKeyPEM, {
            algorithm: 'RS256',
            issuer: 'https://fubar.example.com',
            keyid: oktaKid,
            expiresIn: 3600,
            audience: apiUrl,
        });
        // @ts-ignore
        axios.post.mockResolvedValueOnce({
            data: {
                token_type: 'Bearer',
                expires_in: 3600,
                access_token: invalidAccessToken,
            },
        });
        // okta token
        const accessToken = jsonwebtoken.sign({}, oktaKeys.privateKeyPEM, {
            algorithm: 'RS256',
            issuer: oktaIssuerUrl,
            keyid: oktaKid,
            expiresIn: -3600,
            audience: apiUrl,
        });
        // @ts-ignore
        axios.post.mockResolvedValueOnce({
            data: {
                token_type: 'Bearer',
                expires_in: 3600,
                access_token: accessToken,
            },
        });

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

        let req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
        let res = { status: statusStub } as unknown as express.Response;

        fx(req, res, (err: any) => {
            expect(err).toBeUndefined();

            // we only decode on subsequent cached calls
            req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
            res = { status: statusStub } as unknown as express.Response;
            fx(req, res, (err2: any) => {
                expect(err2).toBeUndefined();

                expect(statusStub).not.toBeCalled();
                expect(req.headers.authorization).toEqual(`Bearer ${accessToken}`);

                done();
            });
        });
    });

    test('multiple cognito jwt calls rewrites', (done) => {
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

        let req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
        let res = { status: statusStub } as unknown as express.Response;

        fx(req, res, (err: any) => {
            expect(err).toBeUndefined();
            expect(req.headers.authorization).not.toEqual(`Bearer ${jwt}`);

            // we only decode on subsequent cached calls
            req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
            res = { status: statusStub } as unknown as express.Response;
            fx(req, res, (err2: any) => {
                expect(err2).toBeUndefined();

                expect(statusStub).not.toBeCalled();
                expect(req.headers.authorization).not.toEqual(`Bearer ${jwt}`);

                done();
            });
        });
    });

    test('cached cognito pem, okta pem and okta access_token rewrites', (done) => {
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

        let req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
        let res = { status: statusStub } as unknown as express.Response;

        fx(req, res, (err: any) => {
            expect(err).toBeUndefined();
            expect(req.headers.authorization).not.toEqual(`Bearer ${jwt}`);

            // we only decode on subsequent cached calls
            req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
            res = { status: statusStub } as unknown as express.Response;
            fx(req, res, (err2: any) => {
                expect(err2).toBeUndefined();

                expect(statusStub).not.toBeCalled();
                expect(axios.get).toBeCalled();

                // @ts-ignore
                expect(axios.get.mock.calls.length).toEqual(2);
                // @ts-ignore
                expect(axios.post).toBeCalled();
                // @ts-ignore
                expect(axios.post.mock.calls.length).toEqual(1);
                expect(req.headers.authorization).not.toEqual(`Bearer ${jwt}`);

                done();
            });
        });
    });

    test('okta token just passed through', (done) => {
        const fx = cognitoRewrite.cognitoRewriteMiddleware(new AWS.SSM());

        // okta token
        const jwt = jsonwebtoken.sign({}, oktaKeys.privateKeyPEM, {
            algorithm: 'RS256',
            issuer: oktaIssuerUrl,
            keyid: oktaKid,
            expiresIn: 3600,
        });

        const req = { headers: { authorization: `Bearer ${jwt}` } } as unknown as express.Request;
        const res = { status: statusStub } as unknown as express.Response;

        fx(req, res, (err: any) => {
            expect(err).toBeUndefined();

            expect(statusStub).not.toBeCalled();
            expect(req.headers.authorization).toEqual(`Bearer ${jwt}`);

            done();
        });
    });
});
