import { encrypt as caesarEncrypt, decrypt as caesarDecrypt } from 'caesar-encrypt'

enum Cryptions {
    xor = "xor",
    base64 = "base64",
    caesar = "caesar",
}

enum Actions {
    encrypt = "encrypt",
    decrypt = "decrypt",
}

abstract class Cryption {
    message: string;
    key?: string;
    abstract encrypt(): string;
    abstract decrypt(): string;

    constructor(message: string, key?: string) {
        this.message = message;
        this.key = key;
    }
}

class XOR extends Cryption {
    encrypt(): string {
        const paddedKey = this.key?.padStart(8, "0")
        return require('xor-crypt')(this.message, paddedKey);
    }

    decrypt(): string {
        return this.encrypt();
    }
}

class Base64 extends Cryption {
    encrypt(): string {
        return btoa(this.message)
    }

    decrypt(): string {
        return atob(this.message)
    }
}

class Caesar extends Cryption {
    encrypt(): string {
        return caesarEncrypt(this.message, this.key)
    }

    decrypt(): string {
        return caesarDecrypt(this.message, this.key)
    }
}

interface CryptionRequest {
    action: string;
    message: string;
    layers: string[];
}

const parseRequest = (): CryptionRequest => {
    var argv = require('minimist')(process.argv.slice(2));
    const action = argv._[0]
    const message = argv._[1]
    const layers = argv.layers.split(/\s*,\s*/);
    return {
        action,
        message,
        layers,
    }
}

const parseLayerKey = (layerKey: string): [layer: string, key: string] => {
    let [layer, key] = ["", ""]

    if (layerKey.includes("=")){
        [layer, key] = layerKey.split("=")
        return [layer, key]
    }

    return [layer, key]
}

const getLayerCryptor = (layerKey: string, message: string): Cryption => {
    let [layer, key] = parseLayerKey(layerKey) 

    switch (layer) {
        case Cryptions.base64:
            return new Base64(message);
        case Cryptions.xor:
            return new XOR(message, key);
        case Cryptions.caesar:
            return new Caesar(message, key);
        default:
            return new Base64(message)
    }
}

const handleRequest = (request: CryptionRequest): string => {
    let message = request.message
    switch (request.action) {
        case Actions.encrypt:
            for (const layer of request.layers) {
                const cryptor = getLayerCryptor(layer, message);
                message = cryptor.encrypt();
            };
            return message;
        case Actions.decrypt:
            for (const layer of request.layers.reverse()) {
                const cryptor = getLayerCryptor(layer, message);
                message = cryptor.decrypt();
            };
            return message;
        };
    return message;
}

const main = (): void => {
    const request = parseRequest()
    const message = handleRequest(request)
    console.log(message)
}

main()