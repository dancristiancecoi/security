/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.tools;

import java.io.Console;
import java.nio.CharBuffer;
import java.util.Objects;

import org.apache.commons.cli.*;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.hash.PasswordHasher;
import org.opensearch.security.hash.PasswordHasherImpl;
import org.opensearch.security.support.ConfigConstants;

import static org.opensearch.security.support.ConfigConstants.*;

public class Hasher {

    private static final String PASSWORD_OPTION = "p";
    private static final String ENV_OPTION = "env";
    private static final String ALGORITHM_OPTION = "a";
    private static final String ROUNDS_OPTION = "r";
    private static final String MINOR_OPTION = "min";
    private static final String VERSION_OPTION = "v";
    private static final String TYPE_OPTION = "t";
    private static final String PARALLELISM_OPTION = "prl";
    private static final String LENGTH_OPTION = "l";
    private static final String ITERATIONS_OPTION = "i";
    private static final String MEMORY_OPTION = "mem";
    private static final String DERIVED_KEY_LENGTH_OPTION = "d";
    private static final String RESOURCES_OPTION = "res";
    private static final String WORK_FACTOR_OPTION = "wf";
    private static final String FUNCTION_OPTION = "f";

    public static void main(final String[] args) {
        final HelpFormatter formatter = new HelpFormatter();
        Options options = buildOptions();
        final CommandLineParser parser = new DefaultParser();
        try {
            final CommandLine line = parser.parse(options, args);
            final char[] password;

            if (line.hasOption(PASSWORD_OPTION)) {
                password = line.getOptionValue(PASSWORD_OPTION).toCharArray();
            } else if (line.hasOption(ENV_OPTION)) {
                final String pwd = System.getenv(line.getOptionValue(ENV_OPTION));
                if (pwd == null || pwd.isEmpty()) {
                    throw new Exception("No environment variable '" + line.getOptionValue(ENV_OPTION) + "' set");
                }
                password = pwd.toCharArray();
            } else {
                final Console console = System.console();
                if (console == null) {
                    throw new Exception("Cannot allocate a console");
                }
                password = console.readPassword("[%s]", "Password:");
            }
            if (line.hasOption(ALGORITHM_OPTION)) {
                String algorithm = line.getOptionValue(ALGORITHM_OPTION);
                Settings settings;
                switch (algorithm.toLowerCase()) {
                    case BCRYPT:
                        settings = getBCryptSettings(line);
                        break;
                    case PBKDF2:
                        settings = getPBKDF2Settings(line);
                        break;
                    case SCRYPT:
                        settings = getSCryptSettings(line);
                        break;
                    case ARGON2:
                        settings = getArgon2Settings(line);
                        break;
                    default:
                        throw new Exception("Unsupported hashing algorithm: " + algorithm);
                }
                System.out.println(hash(password, settings));
            } else {
                System.out.println(hash(password));
            }

        } catch (final Exception exp) {
            System.err.println("Parsing failed.  Reason: " + exp.getMessage());
            formatter.printHelp("hash.sh", options, true);
            System.exit(-1);
        }
    }

    public static String hash(final char[] clearTextPassword) {
        return hash(clearTextPassword, Settings.EMPTY);
    }

    private static String hash(final char[] clearTextPassword, final String algorithm) {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, algorithm).build();
        return hash(clearTextPassword, settings);
    }

    private static String hash(final char[] clearTextPassword, Settings settings) {
        PasswordHasher passwordHasher = new PasswordHasherImpl(settings);
        return passwordHasher.hash((Objects.requireNonNull(CharBuffer.wrap(clearTextPassword))));
    }

    private static Options buildOptions() {
        final Options options = new Options();
        options.addOption(Option.builder(PASSWORD_OPTION).argName("password").hasArg().desc("Cleartext password to hash").build());
        options.addOption(
            Option.builder(ENV_OPTION)
                .argName("name environment variable")
                .hasArg()
                .desc("name environment variable to read password from")
                .build()
        );
        options.addOption(
            Option.builder(ALGORITHM_OPTION)
                .longOpt("algorithm")
                .argName("hashing algorithm")
                .hasArg()
                .desc("Hashing algorithm (BCrypt, PBKDF2, SCrypt, Argon2)")
                .build()
        );
        options.addOption(
            Option.builder(ROUNDS_OPTION)
                .longOpt("rounds")
                .desc("Number of rounds (for BCrypt).")
                .hasArg()
                .argName("rounds")
                .type(Number.class)
                .build()
        );
        options.addOption(
            Option.builder(MINOR_OPTION).longOpt("minor").desc("Minor version (for BCrypt).").hasArg().argName("minor").build()
        );
        options.addOption(
            Option.builder(VERSION_OPTION)
                .longOpt("version")
                .desc("Version of the algorithm (for Argon2).")
                .hasArg()
                .argName("version")
                .type(Number.class)
                .build()
        );
        options.addOption(
            Option.builder(TYPE_OPTION).longOpt("type").desc("Type of the algorithm (for Argon2).").hasArg().argName("type").build()
        );
        options.addOption(
            Option.builder(PARALLELISM_OPTION)
                .longOpt("parallelism")
                .desc("Degree of parallelism (for Argon2, SCrypt).")
                .hasArg()
                .argName("parallelism")
                .type(Number.class)
                .build()
        );
        options.addOption(
            Option.builder(LENGTH_OPTION)
                .longOpt("length")
                .desc("Desired length of the final derived key (for Argon2, PBKDF2).")
                .hasArg()
                .argName("length")
                .type(Number.class)
                .build()
        );
        options.addOption(
            Option.builder(ITERATIONS_OPTION)
                .longOpt("iterations")
                .desc("Iterations to perform (for Argon2, PBKDF2).")
                .hasArg()
                .argName("iterations")
                .type(Number.class)
                .build()
        );
        options.addOption(
            Option.builder(MEMORY_OPTION)
                .longOpt("memory")
                .desc("Memory to use (for Argon2).")
                .hasArg()
                .argName("memory")
                .type(Number.class)
                .build()
        );
        options.addOption(
            Option.builder(DERIVED_KEY_LENGTH_OPTION)
                .longOpt("derived-key-length")
                .desc("Length of the derived key (for SCrypt).")
                .hasArg()
                .argName("length")
                .type(Number.class)
                .build()
        );
        options.addOption(
            Option.builder(RESOURCES_OPTION)
                .longOpt("resources")
                .desc("Resources (for SCrypt).")
                .hasArg()
                .argName("resources")
                .type(Number.class)
                .build()
        );
        options.addOption(
            Option.builder(WORK_FACTOR_OPTION)
                .longOpt("work-factor")
                .desc("Work factor (for SCrypt).")
                .hasArg()
                .argName("work-factor")
                .build()
        );
        options.addOption(
            Option.builder(FUNCTION_OPTION)
                .longOpt("function")
                .desc("Pseudo-random function applied to the password (for PBKDF2).")
                .hasArg()
                .argName("function")
                .build()
        );
        return options;
    }

    private static Settings getBCryptSettings(CommandLine line) throws ParseException {
        Settings.Builder settings = Settings.builder();
        settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, BCRYPT);
        if (line.hasOption(ROUNDS_OPTION)) {
            settings.put(
                ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS,
                ((Number) line.getParsedOptionValue(ROUNDS_OPTION)).intValue()
            );
        }
        if (line.hasOption(MINOR_OPTION)) {
            settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_MINOR, line.getOptionValue(MINOR_OPTION).toUpperCase());
        }
        return settings.build();
    }

    private static Settings getPBKDF2Settings(CommandLine line) throws ParseException {
        Settings.Builder settings = Settings.builder();
        settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, PBKDF2);
        if (line.hasOption(FUNCTION_OPTION)) {
            settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_FUNCTION, line.getOptionValue(FUNCTION_OPTION));
        }
        if (line.hasOption(LENGTH_OPTION)) {
            settings.put(
                ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_LENGTH,
                ((Number) line.getParsedOptionValue(LENGTH_OPTION)).intValue()
            );
        }
        if (line.hasOption(ITERATIONS_OPTION)) {
            settings.put(
                ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_ITERATIONS,
                ((Number) line.getParsedOptionValue(ITERATIONS_OPTION)).intValue()
            );
        }
        return settings.build();
    }

    private static Settings getSCryptSettings(CommandLine line) throws ParseException {
        Settings.Builder settings = Settings.builder();
        settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, SCRYPT);
        if (line.hasOption(DERIVED_KEY_LENGTH_OPTION)) {
            settings.put(
                ConfigConstants.SECURITY_PASSWORD_HASHING_SCRYPT_DERIVED_KEY_LENGTH,
                ((Number) line.getParsedOptionValue(DERIVED_KEY_LENGTH_OPTION)).intValue()
            );
        }
        if (line.hasOption(PARALLELISM_OPTION)) {
            settings.put(
                ConfigConstants.SECURITY_PASSWORD_HASHING_SCRYPT_PARALLELIZATION,
                ((Number) line.getParsedOptionValue(PARALLELISM_OPTION)).intValue()
            );
        }
        if (line.hasOption(RESOURCES_OPTION)) {
            settings.put(
                ConfigConstants.SECURITY_PASSWORD_HASHING_SCRYPT_RESOURCES,
                ((Number) line.getParsedOptionValue(RESOURCES_OPTION)).intValue()
            );
        }
        return settings.build();
    }

    private static Settings getArgon2Settings(CommandLine line) throws ParseException {
        Settings.Builder settings = Settings.builder();
        settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ARGON2);
        if (line.hasOption(VERSION_OPTION)) {
            settings.put(
                ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_VERSION,
                ((Number) line.getParsedOptionValue(VERSION_OPTION)).intValue()
            );
        }
        if (line.hasOption(TYPE_OPTION)) {
            settings.put(ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_TYPE, line.getOptionValue(TYPE_OPTION));
        }
        if (line.hasOption(PARALLELISM_OPTION)) {
            settings.put(
                ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_PARALLELISM,
                ((Number) line.getParsedOptionValue(PARALLELISM_OPTION)).intValue()
            );
        }
        if (line.hasOption(LENGTH_OPTION)) {
            settings.put(
                ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_LENGTH,
                ((Number) line.getParsedOptionValue(LENGTH_OPTION)).intValue()
            );
        }
        if (line.hasOption(ITERATIONS_OPTION)) {
            settings.put(
                ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_ITERATIONS,
                ((Number) line.getParsedOptionValue(ITERATIONS_OPTION)).intValue()
            );
        }
        if (line.hasOption(MEMORY_OPTION)) {
            settings.put(
                ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_MEMORY,
                ((Number) line.getParsedOptionValue(MEMORY_OPTION)).intValue()
            );
        }
        return settings.build();
    }
}
