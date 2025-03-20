"use strict";
/**
 * Encryption module for JnxBetaSec.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.Encryption = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const crypto = __importStar(require("crypto"));
const forge = __importStar(require("node-forge"));
const util_1 = require("util");
const version_1 = require("../version");
// For image metadata extraction
let sharp;
try {
    sharp = require("sharp");
}
catch (e) {
    // Sharp is optional
}
const fsStatPromise = (0, util_1.promisify)(fs.stat);
const fsReadFilePromise = (0, util_1.promisify)(fs.readFile);
const fsWriteFilePromise = (0, util_1.promisify)(fs.writeFile);
const fsMkdirPromise = (0, util_1.promisify)(fs.mkdir);
class Encryption {
    constructor(options) {
        this.FILE_SIGNATURE = Buffer.from("JNXBETASEC");
        this.ITERATIONS = 600000;
        this.KEY_LENGTH = 32; // 256 bits
        this.privateKey = null;
        this.publicKey = null;
        this.userId = options.userId;
        this.organizationId = options.organizationId || "default";
        this.keyDir = options.keyDir || "./secure_keys";
        this.initializeKeys();
    }
    async initializeKeys() {
        try {
            await fsMkdirPromise(this.keyDir, { recursive: true });
            const privateKeyPath = path.join(this.keyDir, `${this.userId}_private.pem`);
            const publicKeyPath = path.join(this.keyDir, `${this.userId}_public.pem`);
            let privateKeyExists = false;
            let publicKeyExists = false;
            try {
                await fsStatPromise(privateKeyPath);
                privateKeyExists = true;
            }
            catch (e) {
                // Private key doesn't exist
            }
            try {
                await fsStatPromise(publicKeyPath);
                publicKeyExists = true;
            }
            catch (e) {
                // Public key doesn't exist
            }
            if (privateKeyExists && publicKeyExists) {
                const privateKeyPem = await fsReadFilePromise(privateKeyPath, "utf8");
                const publicKeyPem = await fsReadFilePromise(publicKeyPath, "utf8");
                this.privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
                this.publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
                console.log(`Loaded existing keys for user ${this.userId}`);
            }
            else {
                console.log(`Generating new RSA key pair for user ${this.userId}...`);
                const keyPair = await new Promise((resolve) => {
                    const keys = forge.pki.rsa.generateKeyPair({ bits: 4096, workers: -1 });
                    resolve(keys);
                });
                this.privateKey = keyPair.privateKey;
                this.publicKey = keyPair.publicKey;
                const privateKeyPem = forge.pki.privateKeyToPem(this.privateKey);
                const publicKeyPem = forge.pki.publicKeyToPem(this.publicKey);
                await fsWriteFilePromise(privateKeyPath, privateKeyPem);
                await fsWriteFilePromise(publicKeyPath, publicKeyPem);
                console.log(`Generated and saved new keys for user ${this.userId}`);
            }
        }
        catch (error) {
            console.error("Error initializing keys:", error);
            throw error;
        }
    }
    async exportKey(keyType, outputPath) {
        if (!this.privateKey || !this.publicKey) {
            await this.initializeKeys();
        }
        if (keyType.toLowerCase() === "public" && this.publicKey) {
            const publicKeyPem = forge.pki.publicKeyToPem(this.publicKey);
            await fsWriteFilePromise(outputPath, publicKeyPem);
        }
        else if (keyType.toLowerCase() === "private" && this.privateKey) {
            const privateKeyPem = forge.pki.privateKeyToPem(this.privateKey);
            await fsWriteFilePromise(outputPath, privateKeyPem);
        }
        else {
            throw new Error("Key type must be 'public' or 'private'");
        }
    }
    deriveKeys(password, salt) {
        const aesKey = crypto.pbkdf2Sync(password, salt, this.ITERATIONS, this.KEY_LENGTH, "sha512");
        const saltHash = crypto.createHash("sha256").update(salt).digest();
        const chachaKey = crypto.pbkdf2Sync(aesKey, saltHash, Math.floor(this.ITERATIONS / 2), this.KEY_LENGTH, "sha512");
        return { aesKey, chachaKey };
    }
    async generateFileMetadata(filePath, contentType) {
        const fileStats = await fsStatPromise(filePath);
        const fileBuffer = await fsReadFilePromise(filePath);
        const fileHash = crypto.createHash("sha512").update(fileBuffer).digest("hex");
        const metadata = {
            filename: path.basename(filePath),
            originalExtension: path.extname(filePath),
            contentType,
            fileSize: fileStats.size,
            createdDate: new Date(fileStats.birthtime).toISOString(),
            modifiedDate: new Date(fileStats.mtime).toISOString(),
            encryptedDate: new Date().toISOString(),
            encryptionVersion: version_1.VERSION,
            sha512Hash: fileHash,
            userId: this.userId,
            organizationId: this.organizationId,
        };
        if (contentType === "image" && sharp) {
            try {
                const imageInfo = await sharp(fileBuffer).metadata();
                metadata.imageWidth = imageInfo.width;
                metadata.imageHeight = imageInfo.height;
                metadata.imageFormat = imageInfo.format;
                metadata.imageMode = imageInfo.space;
            }
            catch (e) {
                console.warn("Could not extract image metadata:", e);
            }
        }
        return metadata;
    }
    async encryptFile(filePath, password, contentType) {
        if (!this.privateKey || !this.publicKey) {
            await this.initializeKeys();
        }
        try {
            await fsStatPromise(filePath);
        }
        catch (e) {
            throw new Error(`File not found: ${filePath}`);
        }
        if (!contentType) {
            const ext = path.extname(filePath).toLowerCase();
            if ([".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp", ".gif"].includes(ext)) {
                contentType = "image";
            }
            else {
                contentType = "text";
            }
        }
        console.log(`Encrypting ${contentType} file: ${filePath}`);
        const salt = crypto.randomBytes(32);
        const aesIv = crypto.randomBytes(12); // 96 bits for AES-GCM
        const chachaNonce = crypto.randomBytes(12); // 96 bits for ChaCha20-Poly1305
        const { aesKey, chachaKey } = this.deriveKeys(password, salt);
        const fileContent = await fsReadFilePromise(filePath);
        const metadata = await this.generateFileMetadata(filePath, contentType);
        const metadataJson = Buffer.from(JSON.stringify(metadata));
        // Layer 1: AES-256-GCM encryption
        const aesGcm = crypto.createCipheriv("aes-256-gcm", aesKey, aesIv);
        aesGcm.setAAD(Buffer.from("JNXL1"));
        let encryptedContent = aesGcm.update(fileContent);
        encryptedContent = Buffer.concat([encryptedContent, aesGcm.final()]);
        const aesAuthTag = aesGcm.getAuthTag();
        // Layer 2: ChaCha20-Poly1305 encryption (using node-forge as Node.js crypto doesn't support ChaCha20-Poly1305 directly)
        const chachaInput = Buffer.concat([encryptedContent, aesAuthTag]);
        const chacha = forge.cipher.createCipher("chacha20-poly1305", forge.util.createBuffer(chachaKey));
        chacha.start({
            iv: forge.util.createBuffer(chachaNonce),
            additionalData: "JNXL2",
        });
        chacha.update(forge.util.createBuffer(chachaInput));
        chacha.finish();
        const doublyEncrypted = Buffer.from(chacha.output.getBytes(), "binary");
        const chachaTag = Buffer.from(chacha.mode.tag.getBytes(), "binary");
        const metaAesGcm = crypto.createCipheriv("aes-256-gcm", aesKey, aesIv);
        metaAesGcm.setAAD(Buffer.from("JNXMETA"));
        let encryptedMetadata = metaAesGcm.update(metadataJson);
        encryptedMetadata = Buffer.concat([encryptedMetadata, metaAesGcm.final()]);
        const metaAuthTag = metaAesGcm.getAuthTag();
        const encryptedMetadataWithTag = Buffer.concat([encryptedMetadata, metaAuthTag]);
        // Layer 3: RSA encryption of the symmetric keys
        const keysBundle = {
            aesKey: aesKey.toString("base64"),
            aesIv: aesIv.toString("base64"),
            chachaKey: chachaKey.toString("base64"),
            chachaNonce: chachaNonce.toString("base64"),
            salt: salt.toString("base64"),
        };
        const keysBundleJson = Buffer.from(JSON.stringify(keysBundle));
        const encryptedKeys = Buffer.from(this.publicKey.encrypt(keysBundleJson.toString("binary"), "RSA-OAEP", {
            md: forge.md.sha512.create(),
            mgf1: {
                md: forge.md.sha512.create(),
            },
        }), "binary");
        const dataToSign = Buffer.concat([doublyEncrypted, chachaTag, encryptedMetadataWithTag]);
        const md = forge.md.sha512.create();
        md.update(dataToSign.toString("binary"));
        const pss = forge.pss.create({
            md: forge.md.sha512.create(),
            mgf: forge.mgf.mgf1.create(forge.md.sha512.create()),
            saltLength: 64, // Maximum for SHA-512
        });
        const signature = Buffer.from(this.privateKey.sign(md, pss), "binary");
        const outputPath = `${filePath}.jnx`;
        const fileStream = fs.createWriteStream(outputPath);
        fileStream.write(this.FILE_SIGNATURE);
        fileStream.write(Buffer.from(version_1.VERSION.padEnd(8, "\0")));
        const keysLenBuffer = Buffer.alloc(4);
        keysLenBuffer.writeUInt32BE(encryptedKeys.length, 0);
        fileStream.write(keysLenBuffer);
        fileStream.write(encryptedKeys);
        const metaLenBuffer = Buffer.alloc(4);
        metaLenBuffer.writeUInt32BE(encryptedMetadataWithTag.length, 0);
        fileStream.write(metaLenBuffer);
        fileStream.write(encryptedMetadataWithTag);
        const sigLenBuffer = Buffer.alloc(4);
        sigLenBuffer.writeUInt32BE(signature.length, 0);
        fileStream.write(sigLenBuffer);
        fileStream.write(signature);
        const contentLenBuffer = Buffer.alloc(8);
        contentLenBuffer.writeBigUInt64BE(BigInt(doublyEncrypted.length + chachaTag.length), 0);
        fileStream.write(contentLenBuffer);
        fileStream.write(doublyEncrypted);
        fileStream.write(chachaTag);
        await new Promise((resolve, reject) => {
            fileStream.on("finish", () => resolve());
            fileStream.on("error", (err) => reject(err));
            fileStream.end();
        });
        console.log(`File successfully encrypted: ${outputPath}`);
        return outputPath;
    }
    async decryptFile(filePath, password, outputPath) {
        if (!this.privateKey || !this.publicKey) {
            await this.initializeKeys();
        }
        try {
            await fsStatPromise(filePath);
        }
        catch (e) {
            throw new Error(`File not found: ${filePath}`);
        }
        if (path.extname(filePath).toLowerCase() !== ".jnx") {
            throw new Error("Not a valid JnxBetaSec file");
        }
        console.log(`Decrypting file: ${filePath}`);
        const fileBuffer = await fsReadFilePromise(filePath);
        let position = 0;
        const signature = fileBuffer.slice(position, position + this.FILE_SIGNATURE.length);
        position += this.FILE_SIGNATURE.length;
        if (!signature.equals(this.FILE_SIGNATURE)) {
            throw new Error("Invalid JnxBetaSec file signature");
        }
        const versionBuffer = fileBuffer.slice(position, position + 8);
        position += 8;
        const version = versionBuffer.toString("utf8").replace(/\0+$/, "");
        if (version !== version_1.VERSION) {
            console.warn(`File version mismatch: ${version} vs ${version_1.VERSION}`);
        }
        const keysLen = fileBuffer.readUInt32BE(position);
        position += 4;
        const encryptedKeys = fileBuffer.slice(position, position + keysLen);
        position += keysLen;
        const metaLen = fileBuffer.readUInt32BE(position);
        position += 4;
        const encryptedMetadataWithTag = fileBuffer.slice(position, position + metaLen);
        position += metaLen;
        const sigLen = fileBuffer.readUInt32BE(position);
        position += 4;
        const fileSignature = fileBuffer.slice(position, position + sigLen);
        position += sigLen;
        const contentLen = Number(fileBuffer.readBigUInt64BE(position));
        position += 8;
        const encryptedContentWithTag = fileBuffer.slice(position, position + contentLen);
        const dataToVerify = Buffer.concat([encryptedContentWithTag, encryptedMetadataWithTag]);
        const md = forge.md.sha512.create();
        md.update(dataToVerify.toString("binary"));
        try {
            const pss = forge.pss.create({
                md: forge.md.sha512.create(),
                mgf: forge.mgf.mgf1.create(forge.md.sha512.create()),
                saltLength: 64,
            });
            const isValid = this.publicKey.verify(md.digest().bytes(), fileSignature.toString("binary"), pss);
            if (!isValid) {
                throw new Error("Invalid file signature - file may be tampered with");
            }
        }
        catch (e) {
            throw new Error("Invalid file signature - file may be tampered with");
        }
        let decryptedKeysBundle;
        try {
            const decryptedKeysBundleJson = this.privateKey.decrypt(encryptedKeys.toString("binary"), "RSA-OAEP", {
                md: forge.md.sha512.create(),
                mgf1: {
                    md: forge.md.sha512.create(),
                },
            });
            decryptedKeysBundle = JSON.parse(decryptedKeysBundleJson);
        }
        catch (e) {
            throw new Error("Failed to decrypt keys - file may be corrupted");
        }
        const aesKey = Buffer.from(decryptedKeysBundle.aesKey, "base64");
        const aesIv = Buffer.from(decryptedKeysBundle.aesIv, "base64");
        const chachaKey = Buffer.from(decryptedKeysBundle.chachaKey, "base64");
        const chachaNonce = Buffer.from(decryptedKeysBundle.chachaNonce, "base64");
        const salt = Buffer.from(decryptedKeysBundle.salt, "base64");
        const { aesKey: derivedAesKey, chachaKey: derivedChachaKey } = this.deriveKeys(password, salt);
        if (!crypto.timingSafeEqual(derivedAesKey, aesKey) || !crypto.timingSafeEqual(derivedChachaKey, chachaKey)) {
            throw new Error("Invalid password");
        }
        // Split encrypted content and ChaCha tag
        const chachaTagLength = 16; // ChaCha20-Poly1305 tag is 16 bytes
        const doublyEncrypted = encryptedContentWithTag.slice(0, encryptedContentWithTag.length - chachaTagLength);
        const chachaTag = encryptedContentWithTag.slice(encryptedContentWithTag.length - chachaTagLength);
        // Layer 2 decryption: ChaCha20-Poly1305
        const chacha = forge.cipher.createDecipher("chacha20-poly1305", forge.util.createBuffer(chachaKey));
        chacha.start({
            iv: forge.util.createBuffer(chachaNonce),
            additionalData: "JNXL2",
            tag: forge.util.createBuffer(chachaTag),
        });
        chacha.update(forge.util.createBuffer(doublyEncrypted));
        const chachaResult = chacha.finish();
        if (!chachaResult) {
            throw new Error("ChaCha20-Poly1305 authentication failed - file may be tampered with");
        }
        const aesEncryptedWithTag = Buffer.from(chacha.output.getBytes(), "binary");
        const aesTagLength = 16; // AES-GCM tag is 16 bytes
        const aesEncrypted = aesEncryptedWithTag.slice(0, aesEncryptedWithTag.length - aesTagLength);
        const aesAuthTag = aesEncryptedWithTag.slice(aesEncryptedWithTag.length - aesTagLength);
        // Layer 1 decryption: AES-256-GCM
        const aesGcm = crypto.createDecipheriv("aes-256-gcm", aesKey, aesIv);
        aesGcm.setAAD(Buffer.from("JNXL1"));
        aesGcm.setAuthTag(aesAuthTag);
        let decryptedContent;
        try {
            decryptedContent = Buffer.concat([aesGcm.update(aesEncrypted), aesGcm.final()]);
        }
        catch (e) {
            throw new Error("AES-GCM authentication failed - file may be tampered with");
        }
        const encryptedMetadata = encryptedMetadataWithTag.slice(0, encryptedMetadataWithTag.length - 16);
        const metaAuthTag = encryptedMetadataWithTag.slice(encryptedMetadataWithTag.length - 16);
        const metaAesGcm = crypto.createDecipheriv("aes-256-gcm", aesKey, aesIv);
        metaAesGcm.setAAD(Buffer.from("JNXMETA"));
        metaAesGcm.setAuthTag(metaAuthTag);
        let decryptedMetadataJson;
        try {
            decryptedMetadataJson = Buffer.concat([metaAesGcm.update(encryptedMetadata), metaAesGcm.final()]);
        }
        catch (e) {
            throw new Error("Metadata authentication failed - file may be tampered with");
        }
        const metadata = JSON.parse(decryptedMetadataJson.toString("utf8"));
        let outputFile;
        if (outputPath) {
            outputFile = outputPath;
        }
        else {
            const outputDir = path.join(path.dirname(filePath), "decrypted");
            await fsMkdirPromise(outputDir, { recursive: true });
            outputFile = path.join(outputDir, metadata.filename);
        }
        await fsWriteFilePromise(outputFile, decryptedContent);
        console.log(`File successfully decrypted: ${outputFile}`);
        return outputFile;
    }
}
exports.Encryption = Encryption;
