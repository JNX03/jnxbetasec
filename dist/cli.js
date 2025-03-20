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
const path = __importStar(require("path"));
const commander_1 = require("commander");
const chalk_1 = __importDefault(require("chalk"));
const inquirer_1 = __importDefault(require("inquirer"));
const ora_1 = __importDefault(require("ora"));
const encryption_1 = require("./core/encryption");
const hashing_1 = require("./core/hashing");
const utils_1 = require("./core/utils");
const version_1 = require("./version");
// Configure logging
const log = {
    info: (message) => console.log(chalk_1.default.blue(message)),
    success: (message) => console.log(chalk_1.default.green(message)),
    warning: (message) => console.log(chalk_1.default.yellow(message)),
    error: (message) => console.error(chalk_1.default.red(message)),
};
commander_1.program.name("jnxbetasec").description("JnxBetaSec - A comprehensive security library").version(version_1.VERSION);
commander_1.program
    .option("--encrypt", "Encrypt a file")
    .option("--decrypt", "Decrypt a file")
    .option("--hash", "Generate a hash for a file")
    .option("--verify", "Verify a file against a hash")
    .option("--generate-keys", "Generate a new key pair")
    .option("--export-key", "Export a key")
    .option("--batch", "Process multiple files")
    .option("--file <path>", "Path to the file")
    .option("--directory <path>", "Path to the directory (for batch operations)")
    .option("--password <password>", "Password for encryption/decryption")
    .option("--algorithm <algorithm>", "Hash algorithm to use", "sha256")
    .option("--hash-value <hash>", "Hash value for verification")
    .option("--user <id>", "User ID for key operations")
    .option("--output <path>", "Output path")
    .option("--type <type>", "Key type (public/private)")
    .option("--recursive", "Process directories recursively")
    .option("--content-type <type>", "Content type (image/text)")
    .option("-v, --verbose", "Enable verbose output");
async function main() {
    commander_1.program.parse();
    const options = commander_1.program.opts();
    // Configure verbosity
    const verbose = options.verbose;
    // No command specified, show help
    if (!options.encrypt &&
        !options.decrypt &&
        !options.hash &&
        !options.verify &&
        !options.generateKeys &&
        !options.exportKey &&
        !options.batch) {
        commander_1.program.help();
        return;
    }
    try {
        // Single file operations
        if (options.encrypt && options.file) {
            let password = options.password;
            if (!password) {
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
                password = answers.password;
            }
            const spinner = (0, ora_1.default)("Encrypting file...").start();
            try {
                const encryptor = new encryption_1.Encryption({
                    userId: options.user || "default_user",
                });
                const result = await encryptor.encryptFile(options.file, password, options.contentType);
                spinner.succeed(`File encrypted: ${result}`);
            }
            catch (error) {
                spinner.fail(`Encryption failed: ${error instanceof Error ? error.message : String(error)}`);
                process.exit(1);
            }
        }
        else if (options.decrypt && options.file) {
            let password = options.password;
            if (!password) {
                const answers = await inquirer_1.default.prompt([
                    {
                        type: "password",
                        name: "password",
                        message: "Enter decryption password:",
                        mask: "*",
                    },
                ]);
                password = answers.password;
            }
            const spinner = (0, ora_1.default)("Decrypting file...").start();
            try {
                const encryptor = new encryption_1.Encryption({
                    userId: options.user || "default_user",
                });
                const result = await encryptor.decryptFile(options.file, password, options.output);
                spinner.succeed(`File decrypted: ${result}`);
            }
            catch (error) {
                spinner.fail(`Decryption failed: ${error instanceof Error ? error.message : String(error)}`);
                process.exit(1);
            }
        }
        else if (options.hash && options.file) {
            const spinner = (0, ora_1.default)("Generating hash...").start();
            try {
                const hasher = new hashing_1.Hashing();
                const result = await hasher.hashFile(options.file, options.algorithm);
                spinner.succeed(`File hash (${options.algorithm}): ${result}`);
            }
            catch (error) {
                spinner.fail(`Hashing failed: ${error instanceof Error ? error.message : String(error)}`);
                process.exit(1);
            }
        }
        else if (options.verify && options.file && options.hashValue) {
            const spinner = (0, ora_1.default)("Verifying file...").start();
            try {
                const hasher = new hashing_1.Hashing();
                const result = await hasher.verifyFile(options.file, options.hashValue, options.algorithm);
                if (result) {
                    spinner.succeed("Verification result: Success");
                }
                else {
                    spinner.fail("Verification result: Failed");
                    process.exit(1);
                }
            }
            catch (error) {
                spinner.fail(`Verification failed: ${error instanceof Error ? error.message : String(error)}`);
                process.exit(1);
            }
        }
        else if (options.generateKeys) {
            const userId = options.user ||
                (await inquirer_1.default
                    .prompt([
                    {
                        type: "input",
                        name: "userId",
                        message: "Enter user ID:",
                        default: "default_user",
                    },
                ])
                    .then((answers) => answers.userId));
            const outputDir = options.output || "./keys";
            const spinner = (0, ora_1.default)(`Generating keys for user ${userId}...`).start();
            try {
                const encryptor = new encryption_1.Encryption({
                    userId,
                    keyDir: outputDir,
                });
                // Force key generation by calling a method
                await encryptor.exportKey("public", path.join(outputDir, `${userId}_public_temp.pem`));
                spinner.succeed(`Keys generated for user ${userId} in ${outputDir}`);
            }
            catch (error) {
                spinner.fail(`Key generation failed: ${error instanceof Error ? error.message : String(error)}`);
                process.exit(1);
            }
        }
        else if (options.exportKey && options.user && options.type) {
            const outputPath = options.output || `./${options.user}_${options.type}.pem`;
            const spinner = (0, ora_1.default)(`Exporting ${options.type} key...`).start();
            try {
                const encryptor = new encryption_1.Encryption({
                    userId: options.user,
                });
                await encryptor.exportKey(options.type, outputPath);
                spinner.succeed(`${options.type.charAt(0).toUpperCase() + options.type.slice(1)} key exported to ${outputPath}`);
            }
            catch (error) {
                spinner.fail(`Key export failed: ${error instanceof Error ? error.message : String(error)}`);
                process.exit(1);
            }
            // Batch operations
        }
        else if (options.batch && options.directory) {
            let password = options.password;
            if (!password && (options.encrypt || options.decrypt)) {
                const answers = await inquirer_1.default.prompt([
                    {
                        type: "password",
                        name: "password",
                        message: `Enter password for batch ${options.encrypt ? "encryption" : "decryption"}:`,
                        mask: "*",
                    },
                ]);
                password = answers.password;
            }
            const processor = new utils_1.BatchProcessor({
                userId: options.user,
            });
            if (options.encrypt) {
                const spinner = (0, ora_1.default)("Batch encrypting files...").start();
                try {
                    const results = await processor.encryptDirectory(options.directory, password, options.recursive, options.contentType);
                    spinner.succeed(`Batch encryption completed: ${results.length} files processed`);
                    if (verbose) {
                        results.forEach((file) => log.info(`Encrypted: ${file}`));
                    }
                }
                catch (error) {
                    spinner.fail(`Batch encryption failed: ${error instanceof Error ? error.message : String(error)}`);
                    process.exit(1);
                }
            }
            else if (options.decrypt) {
                const spinner = (0, ora_1.default)("Batch decrypting files...").start();
                try {
                    const results = await processor.decryptDirectory(options.directory, password, options.recursive, options.output);
                    spinner.succeed(`Batch decryption completed: ${results.length} files processed`);
                    if (verbose) {
                        results.forEach((file) => log.info(`Decrypted: ${file}`));
                    }
                }
                catch (error) {
                    spinner.fail(`Batch decryption failed: ${error instanceof Error ? error.message : String(error)}`);
                    process.exit(1);
                }
            }
            else if (options.hash) {
                const spinner = (0, ora_1.default)(`Generating ${options.algorithm} hashes...`).start();
                try {
                    const results = await processor.hashDirectory(options.directory, options.algorithm, options.recursive);
                    spinner.succeed(`Batch hashing completed: ${Object.keys(results).length} files processed`);
                    // Always show hash results
                    for (const [filePath, fileHash] of Object.entries(results)) {
                        console.log(`${filePath}: ${fileHash}`);
                    }
                }
                catch (error) {
                    spinner.fail(`Batch hashing failed: ${error instanceof Error ? error.message : String(error)}`);
                    process.exit(1);
                }
            }
        }
        else {
            log.error("Invalid command combination. See --help for usage information.");
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
