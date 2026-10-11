/** Unit-test-only synthetic authenticator; production code never imports this file. */
import { generateKeyPairSync, randomBytes, createHash, sign } from 'node:crypto';
import { encodeCBOR } from '@levischuck/tiny-cbor';
import type { CBORType } from '@levischuck/tiny-cbor';
import type { RegistrationResponseJSON, AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/server';
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest();
export class TestAuthenticator {
    readonly keys = generateKeyPairSync('ec', {
        namedCurve: 'prime256v1'
    });
    readonly credentialId = randomBytes(32);
    userId = '';
    counter = 0;
    private authData(rpID: string, flags: number, attested = false) {
        const counter = Buffer.alloc(4);
        counter.writeUInt32BE(this.counter);
        const header = Buffer.concat([hash(rpID), Buffer.from([flags]), counter]);
        if (!attested) {
            return header;
        }
        const key = this.keys.publicKey.export({
            format: 'jwk'
        }), cose = new Map<number, CBORType>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(key.x!, 'base64url')], [-3, Buffer.from(key.y!, 'base64url')]]), length = Buffer.alloc(2);
        length.writeUInt16BE(this.credentialId.length);
        return Buffer.concat([header, Buffer.alloc(16), length, this.credentialId, Buffer.from(encodeCBOR(cose))]);
    }
    register(options: PublicKeyCredentialCreationOptionsJSON, origin: string, overrides: {
        challenge?: string;
        rpID?: string;
        uv?: boolean;
    } = {}): RegistrationResponseJSON {
        this.userId = options.user.id;
        const client = Buffer.from(JSON.stringify({
            type: 'webauthn.create', challenge: overrides.challenge ?? options.challenge, origin, crossOrigin: false
        }));
        const data = this.authData(overrides.rpID ?? options.rp.id!, overrides.uv === false ? 0x41 : 0x45, true);
        const attestation = encodeCBOR(new Map<string, CBORType>([['fmt', 'none'], ['attStmt', new Map()], ['authData', data]]));
        const id = this.credentialId.toString('base64url');
        return {
            id, rawId: id, type: 'public-key', response: {
                clientDataJSON: client.toString('base64url'), attestationObject: Buffer.from(attestation).toString('base64url'), transports: ['internal']
            }, clientExtensionResults: {}
        };
    }
    login(options: PublicKeyCredentialRequestOptionsJSON, origin: string, overrides: {
        challenge?: string;
        rpID?: string;
        uv?: boolean;
        userHandle?: string;
    } = {}): AuthenticationResponseJSON {
        this.counter++;
        const client = Buffer.from(JSON.stringify({
            type: 'webauthn.get', challenge: overrides.challenge ?? options.challenge, origin, crossOrigin: false
        }));
        const data = this.authData(overrides.rpID ?? options.rpId!, overrides.uv === false ? 1 : 5), signature = sign('sha256', Buffer.concat([data, hash(client)]), this.keys.privateKey), id = this.credentialId.toString('base64url');
        return {
            id, rawId: id, type: 'public-key', response: {
                clientDataJSON: client.toString('base64url'), authenticatorData: data.toString('base64url'), signature: signature.toString('base64url'), userHandle: overrides.userHandle ?? this.userId
            }, clientExtensionResults: {}
        };
    }
}
