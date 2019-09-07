import {NativeConnector, NativeConnection} from "native-messaging-connector";
import * as nacl from "tweetnacl";
import * as util from "tweetnacl-util";

enum Actions {
    SET_LOGIN = 'set-login',
    GET_LOGINS = 'get-logins',
    GENERATE_PASSWORD = 'generate-password',
    ASSOCIATE = 'associate',
    TEST_ASSOCIATE = 'test-associate',
    GET_DATABASE_HASH = 'get-databasehash',
    CHANGE_PUBLIC_KEYS = 'change-public-keys',
    LOCK_DATABASE = 'lock-database',
    DATABASE_LOCKED = 'database-locked',
    DATABASE_UNLOCKED = 'database-unlocked',
    GET_DATABASE_GROUPS = 'get-database-groups',
    CREATE_NEW_GROUP = 'create-new-group',
}

const KEY_SIZE = 24;

function getNonce() {
    return util.encodeBase64(nacl.randomBytes(KEY_SIZE));
}

function incrementedNonce(nonce: string) {
    const oldNonce = util.decodeBase64(nonce);
    let newNonce = oldNonce.slice(0);

    // from libsodium/utils.c
    let i = 0;
    let c = 1;
    for (; i < newNonce.length; ++i) {
        c += newNonce[i];
        newNonce[i] = c;
        c >>= 8;
    }

    return util.encodeBase64(newNonce);
}

function checkNonceLength(nonce: string) {
    return util.decodeBase64(nonce).length === nacl.secretbox.nonceLength;
}

function verifyMessage(message: { nonce: string }, expectedNone: string) {
    if (!checkNonceLength(message.nonce)) {
        return false;
    }

    return message.nonce === expectedNone;
}

interface BasicResponse {
    action: Actions;
}

interface EncryptedResponse extends BasicResponse {
    message: string;
    nonce: string;
    clientID: string;
    error?: string;
    errorCode?: number;
}

interface ResponseBase extends BasicResponse {
    success: boolean;
    version: string;
    nonce: string;
}

interface ChangePublicKeyResponse extends ResponseBase {
    publicKey: string;
}

interface GetDatabaseHashResponse extends ResponseBase {
    hash: string;
}

interface AssociateResponse extends ResponseBase {
    hash: string;
    id: string;
}

interface LoginEntry {
    login: string;
    name: string;
    password: string;
    expired: boolean;
}

interface GetLoginsResponse extends ResponseBase {
    count: number;
    entries: Array<LoginEntry>;
}

type TestAssociateResponse = AssociateResponse;

interface AssociationVars {
    id: string;
    idKey: string;
}

export class KeepassXCConnection {
    private _connection: NativeConnection;
    private _keyPair: nacl.BoxKeyPair;
    private readonly _clientID: string;
    private _version: string;
    private _serverPublicKey: Uint8Array;
    private _association: AssociationVars;

    public static async create(): Promise<KeepassXCConnection> {
        const connector = await NativeConnector.create("org.keepassxc.keepassxc_browser");

        const connection = connector.connect();

        return new KeepassXCConnection(connection);
    }

    constructor(connection: NativeConnection) {
        this._connection = connection;

        this._keyPair = nacl.box.keyPair();

        this._clientID = util.encodeBase64(nacl.randomBytes(KEY_SIZE));
    }

    public disconnect() {
        this._connection.disconnect();
    }

    private verifyKeyResponse(response: ChangePublicKeyResponse, expectedNonce: string) {
        if (!verifyMessage(response, expectedNonce)) {
            return false;
        }

        if (!response.success || !response.publicKey) {
            return false;
        }

        let reply = false;

        if (response.publicKey) {
            this._serverPublicKey = util.decodeBase64(response.publicKey);
            reply = true;
        }

        return reply;
    }

    private encrypt(input: any, nonce: string): string {
        const messageData = util.decodeUTF8(JSON.stringify(input));
        const messageNonce = util.decodeBase64(nonce);

        if (this._serverPublicKey) {
            const message = nacl.box(messageData, messageNonce, this._serverPublicKey, this._keyPair.secretKey);
            if (message) {
                return util.encodeBase64(message);
            }
        }
        return '';
    }

    private decrypt(input: string, nonce: string): any {
        const m = util.decodeBase64(input);
        const n = util.decodeBase64(nonce);
        return nacl.box.open(m, n, this._serverPublicKey, this._keyPair.secretKey);
    }

    private async verifyKeys(): Promise<boolean> {
        if (!this._serverPublicKey) {
            if (!await this.changePublicKeys()) {
                return false;
            }
        }

        return true;
    }

    private async sendMessage<T>(action: Actions, timeout: number = 2000, message: any = null): Promise<T> {
        const nonce = getNonce();
        const incNonce = incrementedNonce(nonce);

        let messageData = {
            action: action,
        };

        if (message !== null) {
            messageData = Object.assign(messageData, message);
        }
        const encrypted = this.encrypt(messageData, nonce);
        if (encrypted.length <= 0) {
            throw new Error("Encryption failed!");
        }

        const request = {
            action: action,
            message: encrypted,
            nonce: nonce,
            clientID: this._clientID,
        };

        await this._connection.sendMessage(request);

        let response: EncryptedResponse;
        do {
            response = await this._connection.readMessage<EncryptedResponse>(timeout);

            // Check if maybe we received a signal in the mean time
            if (response.action != action) {
                KeepassXCConnection.dispatchSignal(response);
            } else {
                break;
            }
        } while (true);

        if (response.message && response.nonce) {
            const decryptedRes = this.decrypt(response.message, response.nonce);
            if (!decryptedRes) {
                throw new Error("Decryption failed!");
            }

            const message = util.encodeUTF8(decryptedRes);
            const parsed = JSON.parse(message);

            if (!verifyMessage(parsed, incNonce)) {
                throw new Error("Message verification failed!");
            }

            return parsed as T;
        } else if (response.error) {
            throw new Error("Action failed with code " + (response.errorCode || "<Unspecified>") + ": " + response.error);
        } else {
            throw new Error("Response missed important fields!");
        }
    }

    public async changePublicKeys() {
        const key = util.encodeBase64(this._keyPair.publicKey);
        const nonce = getNonce();
        const incNonce = incrementedNonce(nonce);

        const request = {
            action: Actions.CHANGE_PUBLIC_KEYS,
            publicKey: key,
            nonce: nonce,
            clientID: this._clientID
        };

        await this._connection.sendMessage(request);

        let response: ResponseBase;
        do {
            response = await this._connection.readMessage<ResponseBase>(2000);

            // Check if maybe we received a signal in the mean time
            if (response.action != Actions.CHANGE_PUBLIC_KEYS) {
                KeepassXCConnection.dispatchSignal(response);
            } else {
                break;
            }
        } while (true);

        this._version = response.version;

        return this.verifyKeyResponse(response as ChangePublicKeyResponse, incNonce);
    }

    public async getDatabaseHash(): Promise<string> {
        if (!await this.verifyKeys()) {
            return null;
        }

        const response = await this.sendMessage<GetDatabaseHashResponse>(Actions.GET_DATABASE_HASH);

        if (!response.success) {
            return null;
        }

        this._version = response.version;

        return response.hash;
    }

    public async associate(): Promise<{ id: string, idKey: string, dbHash: string }> {
        if (!await this.verifyKeys()) {
            return null;
        }

        const associateKeyPair = nacl.box.keyPair();

        // Association can take indefinite time since user interaction is required
        const response = await this.sendMessage<AssociateResponse>(Actions.ASSOCIATE, null, {
            key: util.encodeBase64(this._keyPair.publicKey),
            idKey: util.encodeBase64(associateKeyPair.publicKey),
        });

        const id = response.id;
        const idKey = util.encodeBase64(associateKeyPair.publicKey);

        this._association = {
            id: id,
            idKey: idKey,
        };

        return {
            id: id,
            idKey: idKey,
            dbHash: response.hash,
        };
    }

    public async testAssociate(id: string, idKey: string) {
        if (!await this.verifyKeys()) {
            return null;
        }

        const response = await this.sendMessage<TestAssociateResponse>(Actions.TEST_ASSOCIATE, 2000, {
            id: id,
            key: idKey,
        });

        this._association = {
            id: id,
            idKey: idKey,
        };

        return response.success;
    }

    public async getLogins(url: string): Promise<Array<LoginEntry>> {
        if (!await this.verifyKeys()) {
            return null;
        }

        const response = await this.sendMessage<GetLoginsResponse>(Actions.GET_LOGINS, 2000, {
            url: url,
            keys: [
                {
                    id: this._association.id,
                    key: this._association.id,
                }
            ]
        });

        return response.entries;
    }

    private static dispatchSignal(response: BasicResponse) {
        console.log("Received signal: " + JSON.stringify(response));
    }
}