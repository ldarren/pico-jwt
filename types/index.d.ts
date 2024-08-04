/// <reference types="node" />

declare module 'pico-jwt' {
    import { KeyObject } from 'crypto';

    type Callback = (err: Error | null, key?: string | Buffer | undefined) => void;
    type Algorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512' | 'PS256' | 'PS384' | 'PS512';

    interface JWTHeader {
        typ?: string;
        alg: Algorithm;
        [key: string]: any;
    }

    interface JWTPayload {
        [key: string]: any;
    }

    class JWT {
        constructor(algo: Algorithm, secret: string | Buffer, key?: string | Buffer);
        addKeys(secret: string | Buffer, key?: string | Buffer, cb?: Callback): void;
        create(payload: JWTPayload, header?: Partial<JWTHeader>): string;
        header(jwt: string): JWTHeader | undefined;
        payload(jwt: string): JWTPayload | undefined;
        verify(jwt: string): boolean;
    }

    export = JWT;
}

