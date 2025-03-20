#!/usr/bin/env node
import * as path from "path"
import { program } from "commander"
import chalk from "chalk"
import inquirer from "inquirer"
import ora from "ora"
import { Encryption } from "./core/encryption"
import { Hashing } from "./core/hashing"
import { BatchProcessor } from "./core/utils"
import { VERSION } from "./version"
import type { HashAlgorithm, ContentType } from "./types"

// Configure logging
const log = {
  info: (message: string) => console.log(chalk.blue(message)),
  success: (message: string) => console.log(chalk.green(message)),
  warning: (message: string) => console.log(chalk.yellow(message)),
  error: (message: string) => console.error(chalk.red(message)),
}

program.name("jnxbetasec").description("JnxBetaSec - A comprehensive security library").version(VERSION)

program
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
  .option("-v, --verbose", "Enable verbose output")

async function main() {
  program.parse()
  const options = program.opts()

  // Configure verbosity
  const verbose = options.verbose

  // No command specified, show help
  if (
    !options.encrypt &&
    !options.decrypt &&
    !options.hash &&
    !options.verify &&
    !options.generateKeys &&
    !options.exportKey &&
    !options.batch
  ) {
    program.help()
    return
  }

  try {
    // Single file operations
    if (options.encrypt && options.file) {
      let password = options.password
      if (!password) {
        const answers = await inquirer.prompt([
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
        ])

        if (answers.password !== answers.confirmPassword) {
          log.error("Passwords do not match")
          process.exit(1)
        }

        password = answers.password
      }

      const spinner = ora("Encrypting file...").start()

      try {
        const encryptor = new Encryption({
          userId: options.user || "default_user",
        })

        const result = await encryptor.encryptFile(options.file, password, options.contentType as ContentType)

        spinner.succeed(`File encrypted: ${result}`)
      } catch (error) {
        spinner.fail(`Encryption failed: ${error instanceof Error ? error.message : String(error)}`)
        process.exit(1)
      }
    } else if (options.decrypt && options.file) {
      let password = options.password
      if (!password) {
        const answers = await inquirer.prompt([
          {
            type: "password",
            name: "password",
            message: "Enter decryption password:",
            mask: "*",
          },
        ])

        password = answers.password
      }

      const spinner = ora("Decrypting file...").start()

      try {
        const encryptor = new Encryption({
          userId: options.user || "default_user",
        })

        const result = await encryptor.decryptFile(options.file, password, options.output)

        spinner.succeed(`File decrypted: ${result}`)
      } catch (error) {
        spinner.fail(`Decryption failed: ${error instanceof Error ? error.message : String(error)}`)
        process.exit(1)
      }
    } else if (options.hash && options.file) {
      const spinner = ora("Generating hash...").start()

      try {
        const hasher = new Hashing()
        const result = await hasher.hashFile(options.file, options.algorithm as HashAlgorithm)

        spinner.succeed(`File hash (${options.algorithm}): ${result}`)
      } catch (error) {
        spinner.fail(`Hashing failed: ${error instanceof Error ? error.message : String(error)}`)
        process.exit(1)
      }
    } else if (options.verify && options.file && options.hashValue) {
      const spinner = ora("Verifying file...").start()

      try {
        const hasher = new Hashing()
        const result = await hasher.verifyFile(options.file, options.hashValue, options.algorithm as HashAlgorithm)

        if (result) {
          spinner.succeed("Verification result: Success")
        } else {
          spinner.fail("Verification result: Failed")
          process.exit(1)
        }
      } catch (error) {
        spinner.fail(`Verification failed: ${error instanceof Error ? error.message : String(error)}`)
        process.exit(1)
      }
    } else if (options.generateKeys) {
      const userId =
        options.user ||
        (await inquirer
          .prompt([
            {
              type: "input",
              name: "userId",
              message: "Enter user ID:",
              default: "default_user",
            },
          ])
          .then((answers) => answers.userId))

      const outputDir = options.output || "./keys"

      const spinner = ora(`Generating keys for user ${userId}...`).start()

      try {
        const encryptor = new Encryption({
          userId,
          keyDir: outputDir,
        })

        // Force key generation by calling a method
        await encryptor.exportKey("public", path.join(outputDir, `${userId}_public_temp.pem`))

        spinner.succeed(`Keys generated for user ${userId} in ${outputDir}`)
      } catch (error) {
        spinner.fail(`Key generation failed: ${error instanceof Error ? error.message : String(error)}`)
        process.exit(1)
      }
    } else if (options.exportKey && options.user && options.type) {
      const outputPath = options.output || `./${options.user}_${options.type}.pem`

      const spinner = ora(`Exporting ${options.type} key...`).start()

      try {
        const encryptor = new Encryption({
          userId: options.user,
        })

        await encryptor.exportKey(options.type, outputPath)

        spinner.succeed(`${options.type.charAt(0).toUpperCase() + options.type.slice(1)} key exported to ${outputPath}`)
      } catch (error) {
        spinner.fail(`Key export failed: ${error instanceof Error ? error.message : String(error)}`)
        process.exit(1)
      }

      // Batch operations
    } else if (options.batch && options.directory) {
      let password = options.password
      if (!password && (options.encrypt || options.decrypt)) {
        const answers = await inquirer.prompt([
          {
            type: "password",
            name: "password",
            message: `Enter password for batch ${options.encrypt ? "encryption" : "decryption"}:`,
            mask: "*",
          },
        ])

        password = answers.password
      }

      const processor = new BatchProcessor({
        userId: options.user,
      })

      if (options.encrypt) {
        const spinner = ora("Batch encrypting files...").start()

        try {
          const results = await processor.encryptDirectory(
            options.directory,
            password!,
            options.recursive,
            options.contentType as ContentType,
          )

          spinner.succeed(`Batch encryption completed: ${results.length} files processed`)

          if (verbose) {
            results.forEach((file) => log.info(`Encrypted: ${file}`))
          }
        } catch (error) {
          spinner.fail(`Batch encryption failed: ${error instanceof Error ? error.message : String(error)}`)
          process.exit(1)
        }
      } else if (options.decrypt) {
        const spinner = ora("Batch decrypting files...").start()

        try {
          const results = await processor.decryptDirectory(
            options.directory,
            password!,
            options.recursive,
            options.output,
          )

          spinner.succeed(`Batch decryption completed: ${results.length} files processed`)

          if (verbose) {
            results.forEach((file) => log.info(`Decrypted: ${file}`))
          }
        } catch (error) {
          spinner.fail(`Batch decryption failed: ${error instanceof Error ? error.message : String(error)}`)
          process.exit(1)
        }
      } else if (options.hash) {
        const spinner = ora(`Generating ${options.algorithm} hashes...`).start()

        try {
          const results = await processor.hashDirectory(
            options.directory,
            options.algorithm as HashAlgorithm,
            options.recursive,
          )

          spinner.succeed(`Batch hashing completed: ${Object.keys(results).length} files processed`)

          // Always show hash results
          for (const [filePath, fileHash] of Object.entries(results)) {
            console.log(`${filePath}: ${fileHash}`)
          }
        } catch (error) {
          spinner.fail(`Batch hashing failed: ${error instanceof Error ? error.message : String(error)}`)
          process.exit(1)
        }
      }
    } else {
      log.error("Invalid command combination. See --help for usage information.")
      process.exit(1)
    }
  } catch (error) {
    log.error(`Error: ${error instanceof Error ? error.message : String(error)}`)
    process.exit(1)
  }
}

// Run the CLI
main().catch((error) => {
  log.error(`Unhandled error: ${error instanceof Error ? error.message : String(error)}`)
  process.exit(1)
})

