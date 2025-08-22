#!/usr/bin/env node
"use strict";
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs = __importStar(require("fs"));
const crypto = __importStar(require("crypto"));
const commander_1 = require("commander");
const chalk_1 = __importDefault(require("chalk"));
const inquirer_1 = __importDefault(require("inquirer"));
const ora_1 = __importDefault(require("ora"));
const encryption_1 = require("./core/encryption");
const hashing_1 = require("./core/hashing");
const version_1 = require("./version");
// Configure logging
const log = {
    info: (message) => console.log(chalk_1.default.blue(message)),
    success: (message) => console.log(chalk_1.default.green(message)),
    warning: (message) => console.log(chalk_1.default.yellow(message)),
    error: (message) => console.error(chalk_1.default.red(message)),
};
// Security utilities
class SecurityUtils {
    static generatePassword(length = 32, includeSymbols = true) {
        const lowercase = 'abcdefghijklmnopqrstuvwxyz';
        const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const numbers = '0123456789';
        const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        let charset = lowercase + uppercase + numbers;
        if (includeSymbols)
            charset += symbols;
        let password = '';
        for (let i = 0; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        return password;
    }
    static secureDelete(filePath) {
        try {
            const stats = fs.statSync(filePath);
            const fileSize = stats.size;
            // Overwrite with random data 3 times
            for (let i = 0; i < 3; i++) {
                const randomData = crypto.randomBytes(fileSize);
                fs.writeFileSync(filePath, randomData);
            }
            // Finally delete the file
            fs.unlinkSync(filePath);
            return true;
        }
        catch (error) {
            return false;
        }
    }
    static validateCertificate(certPath) {
        try {
            const certData = fs.readFileSync(certPath, 'utf8');
            // Basic certificate validation
            const isValidFormat = certData.includes('-----BEGIN CERTIFICATE-----') &&
                certData.includes('-----END CERTIFICATE-----');
            return {
                valid: isValidFormat,
                details: {
                    format: isValidFormat ? 'PEM' : 'Unknown',
                    size: certData.length,
                    path: certPath
                }
            };
        }
        catch (error) {
            return { valid: false, details: { error: error instanceof Error ? error.message : String(error) } };
        }
    }
    static scanNetworkPorts(host, ports) {
        return new Promise((resolve) => {
            const net = require('net');
            const open = [];
            const closed = [];
            let completed = 0;
            ports.forEach(port => {
                const socket = new net.Socket();
                const timeout = 3000;
                socket.setTimeout(timeout);
                socket.on('connect', () => {
                    open.push(port);
                    socket.destroy();
                    completed++;
                    if (completed === ports.length)
                        resolve({ open, closed });
                });
                socket.on('timeout', () => {
                    closed.push(port);
                    socket.destroy();
                    completed++;
                    if (completed === ports.length)
                        resolve({ open, closed });
                });
                socket.on('error', () => {
                    closed.push(port);
                    completed++;
                    if (completed === ports.length)
                        resolve({ open, closed });
                });
                socket.connect(port, host);
            });
        });
    }
    static analyzeLogFile(logPath, pattern) {
        try {
            const logData = fs.readFileSync(logPath, 'utf8');
            const lines = logData.split('\n');
            const regex = new RegExp(pattern, 'gi');
            const matchingLines = lines.filter(line => regex.test(line));
            return {
                matches: matchingLines.length,
                lines: matchingLines.slice(0, 50) // Limit to first 50 matches
            };
        }
        catch (error) {
            return { matches: 0, lines: [] };
        }
    }
    static compressFile(filePath, outputPath) {
        const zlib = require('zlib');
        const inputBuffer = fs.readFileSync(filePath);
        const compressed = zlib.gzipSync(inputBuffer);
        const output = outputPath || `${filePath}.gz`;
        fs.writeFileSync(output, compressed);
        return output;
    }
    static decompressFile(filePath, outputPath) {
        const zlib = require('zlib');
        const inputBuffer = fs.readFileSync(filePath);
        const decompressed = zlib.gunzipSync(inputBuffer);
        const output = outputPath || filePath.replace('.gz', '');
        fs.writeFileSync(output, decompressed);
        return output;
    }
}
commander_1.program.name("securekit").description("SecureKit - A comprehensive security toolkit with advanced features").version(version_1.VERSION);
commander_1.program
    .option("--type <type>", "Operation type: encryption, decryption, hash, verify, password, secure-delete, compress, decompress, network-scan, cert-validate, log-analysis, integrity-check")
    .option("--file <path>", "Path to the file")
    .option("--directory <path>", "Path to the directory (for batch operations)")
    .option("--password <password>", "Password for encryption/decryption")
    .option("--algorithm <algorithm>", "Hash algorithm to use", "sha256")
    .option("--hash-value <hash>", "Hash value for verification")
    .option("--user <id>", "User ID for key operations")
    .option("--output <path>", "Output path")
    .option("--key-type <type>", "Key type (public/private)")
    .option("--recursive", "Process directories recursively")
    .option("--content-type <type>", "Content type (image/text)")
    .option("--length <number>", "Password length (default: 32)", "32")
    .option("--include-symbols", "Include symbols in password generation")
    .option("--host <host>", "Host for network operations")
    .option("--ports <ports>", "Comma-separated list of ports to scan")
    .option("--pattern <pattern>", "Pattern for log analysis")
    .option("--overwrite-passes <number>", "Number of overwrite passes for secure deletion", "3")
    .option("--batch", "Enable batch processing")
    .option("-v, --verbose", "Enable verbose output");
async function main() {
    commander_1.program.parse();
    const options = commander_1.program.opts();
    // Configure verbosity
    const verbose = options.verbose;
    // Show help if no operation type specified
    if (!options.type) {
        commander_1.program.help();
        return;
    }
    // Input validation
    const sanitizeInput = (input) => {
        return input.replace(/[<>:"'|?*\x00-\x1f]/g, '').trim();
    };
    try {
        switch (options.type.toLowerCase()) {
            case 'encryption':
                if (!options.file) {
                    log.error("File path required for encryption");
                    process.exit(1);
                }
                let encPassword = options.password;
                if (!encPassword) {
                    const answers = await inquirer_1.default.prompt([
                        {
                            type: "password",
                            name: "password",
                            message: "Enter encryption password:",
                            mask: "*",
                        },
                        {
                            type: "password",
                            name: "confirmPassword",
                            message: "Confirm encryption password:",
                            mask: "*",
                        },
                    ]);
                    if (answers.password !== answers.confirmPassword) {
                        log.error("Passwords do not match");
                        process.exit(1);
                    }
                    encPassword = answers.password;
                }
                const spinner1 = (0, ora_1.default)("Encrypting file...").start();
                try {
                    const encryptor = new encryption_1.Encryption({
                        userId: sanitizeInput(options.user || "default_user"),
                    });
                    const result = await encryptor.encryptFile(sanitizeInput(options.file), encPassword, options.contentType);
                    spinner1.succeed(`File encrypted: ${result}`);
                }
                catch (error) {
                    spinner1.fail(`Encryption failed: ${error instanceof Error ? error.message : String(error)}`);
                    process.exit(1);
                }
                break;
            case 'decryption':
                if (!options.file) {
                    log.error("File path required for decryption");
                    process.exit(1);
                }
                let decPassword = options.password;
                if (!decPassword) {
                    const answers = await inquirer_1.default.prompt([
                        {
                            type: "password",
                            name: "password",
                            message: "Enter decryption password:",
                            mask: "*",
                        },
                    ]);
                    decPassword = answers.password;
                }
                const spinner2 = (0, ora_1.default)("Decrypting file...").start();
                try {
                    const encryptor = new encryption_1.Encryption({
                        userId: sanitizeInput(options.user || "default_user"),
                    });
                    const result = await encryptor.decryptFile(sanitizeInput(options.file), decPassword, options.output ? sanitizeInput(options.output) : undefined);
                    spinner2.succeed(`File decrypted: ${result}`);
                }
                catch (error) {
                    spinner2.fail(`Decryption failed: ${error instanceof Error ? error.message : String(error)}`);
                    process.exit(1);
                }
                break;
            case 'hash':
                if (!options.file) {
                    log.error("File path required for hashing");
                    process.exit(1);
                }
                const spinner3 = (0, ora_1.default)("Generating hash...").start();
                try {
                    const hasher = new hashing_1.Hashing();
                    const result = await hasher.hashFile(sanitizeInput(options.file), sanitizeInput(options.algorithm));
                    spinner3.succeed(`File hash (${options.algorithm}): ${result}`);
                }
                catch (error) {
                    spinner3.fail(`Hashing failed: ${error instanceof Error ? error.message : String(error)}`);
                    process.exit(1);
                }
                break;
            case 'verify':
                if (!options.file || !options.hashValue) {
                    log.error("File path and hash value required for verification");
                    process.exit(1);
                }
                const spinner4 = (0, ora_1.default)("Verifying file...").start();
                try {
                    const hasher = new hashing_1.Hashing();
                    const result = await hasher.verifyFile(sanitizeInput(options.file), sanitizeInput(options.hashValue), sanitizeInput(options.algorithm));
                    if (result) {
                        spinner4.succeed("Verification result: Success");
                    }
                    else {
                        spinner4.fail("Verification result: Failed");
                        process.exit(1);
                    }
                }
                catch (error) {
                    spinner4.fail(`Verification failed: ${error instanceof Error ? error.message : String(error)}`);
                    process.exit(1);
                }
                break;
            case 'password':
                const length = parseInt(options.length) || 32;
                const includeSymbols = options.includeSymbols || false;
                const password = SecurityUtils.generatePassword(length, includeSymbols);
                log.success(`Generated password: ${password}`);
                log.info(`Password strength: ${length} characters, ${includeSymbols ? 'with' : 'without'} symbols`);
                break;
            case 'secure-delete':
                if (!options.file) {
                    log.error("File path required for secure deletion");
                    process.exit(1);
                }
                const spinner5 = (0, ora_1.default)("Securely deleting file...").start();
                const deleteResult = SecurityUtils.secureDelete(sanitizeInput(options.file));
                if (deleteResult) {
                    spinner5.succeed("File securely deleted");
                }
                else {
                    spinner5.fail("Secure deletion failed");
                    process.exit(1);
                }
                break;
            case 'compress':
                if (!options.file) {
                    log.error("File path required for compression");
                    process.exit(1);
                }
                const spinner6 = (0, ora_1.default)("Compressing file...").start();
                try {
                    const compressedFile = SecurityUtils.compressFile(sanitizeInput(options.file), options.output ? sanitizeInput(options.output) : undefined);
                    spinner6.succeed(`File compressed: ${compressedFile}`);
                }
                catch (error) {
                    spinner6.fail(`Compression failed: ${error instanceof Error ? error.message : String(error)}`);
                    process.exit(1);
                }
                break;
            case 'decompress':
                if (!options.file) {
                    log.error("File path required for decompression");
                    process.exit(1);
                }
                const spinner7 = (0, ora_1.default)("Decompressing file...").start();
                try {
                    const decompressedFile = SecurityUtils.decompressFile(sanitizeInput(options.file), options.output ? sanitizeInput(options.output) : undefined);
                    spinner7.succeed(`File decompressed: ${decompressedFile}`);
                }
                catch (error) {
                    spinner7.fail(`Decompression failed: ${error instanceof Error ? error.message : String(error)}`);
                    process.exit(1);
                }
                break;
            case 'network-scan':
                if (!options.host || !options.ports) {
                    log.error("Host and ports required for network scanning");
                    process.exit(1);
                }
                const ports = options.ports.split(',').map((p) => parseInt(p.trim())).filter((p) => !isNaN(p));
                const spinner8 = (0, ora_1.default)(`Scanning ${ports.length} ports on ${options.host}...`).start();
                try {
                    const scanResult = await SecurityUtils.scanNetworkPorts(sanitizeInput(options.host), ports);
                    spinner8.succeed(`Network scan completed`);
                    log.success(`Open ports: ${scanResult.open.join(', ') || 'None'}`);
                    log.info(`Closed ports: ${scanResult.closed.length}`);
                }
                catch (error) {
                    spinner8.fail(`Network scan failed: ${error instanceof Error ? error.message : String(error)}`);
                    process.exit(1);
                }
                break;
            case 'cert-validate':
                if (!options.file) {
                    log.error("Certificate file path required");
                    process.exit(1);
                }
                const spinner9 = (0, ora_1.default)("Validating certificate...").start();
                try {
                    const certResult = SecurityUtils.validateCertificate(sanitizeInput(options.file));
                    if (certResult.valid) {
                        spinner9.succeed("Certificate is valid");
                        if (verbose) {
                            log.info(`Certificate details: ${JSON.stringify(certResult.details, null, 2)}`);
                        }
                    }
                    else {
                        spinner9.fail("Certificate validation failed");
                        log.error(`Error: ${certResult.details.error || 'Invalid format'}`);
                        process.exit(1);
                    }
                }
                catch (error) {
                    spinner9.fail(`Certificate validation failed: ${error instanceof Error ? error.message : String(error)}`);
                    process.exit(1);
                }
                break;
            case 'log-analysis':
                if (!options.file || !options.pattern) {
                    log.error("Log file path and search pattern required");
                    process.exit(1);
                }
                const spinner10 = (0, ora_1.default)("Analyzing log file...").start();
                try {
                    const logResult = SecurityUtils.analyzeLogFile(sanitizeInput(options.file), sanitizeInput(options.pattern));
                    spinner10.succeed(`Log analysis completed: ${logResult.matches} matches found`);
                    if (logResult.matches > 0 && verbose) {
                        log.info("Matching lines:");
                        logResult.lines.forEach((line, index) => {
                            console.log(`${index + 1}: ${line}`);
                        });
                    }
                }
                catch (error) {
                    spinner10.fail(`Log analysis failed: ${error instanceof Error ? error.message : String(error)}`);
                    process.exit(1);
                }
                break;
            case 'integrity-check':
                if (!options.file) {
                    log.error("File path required for integrity check");
                    process.exit(1);
                }
                const spinner11 = (0, ora_1.default)("Checking file integrity...").start();
                try {
                    const hasher = new hashing_1.Hashing();
                    const hash1 = await hasher.hashFile(sanitizeInput(options.file), 'sha256');
                    // Wait a moment and hash again to ensure consistency
                    await new Promise(resolve => setTimeout(resolve, 100));
                    const hash2 = await hasher.hashFile(sanitizeInput(options.file), 'sha256');
                    if (hash1 === hash2) {
                        spinner11.succeed("File integrity check passed");
                        log.success(`File hash: ${hash1}`);
                    }
                    else {
                        spinner11.fail("File integrity check failed - file may be corrupted");
                        process.exit(1);
                    }
                }
                catch (error) {
                    spinner11.fail(`Integrity check failed: ${error instanceof Error ? error.message : String(error)}`);
                    process.exit(1);
                }
                break;
            default:
                log.error(`Unknown operation type: ${options.type}`);
                log.info("Available types: encryption, decryption, hash, verify, password, secure-delete, compress, decompress, network-scan, cert-validate, log-analysis, integrity-check");
                process.exit(1);
        }
    }
    catch (error) {
        log.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
        process.exit(1);
    }
}
// Run the CLI
main().catch((error) => {
    log.error(`Unhandled error: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
});
