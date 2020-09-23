#!/usr/bin/env node
import {KeepassXCConnection} from "./KeepassXCConnection";
import {Configuration} from "./Configuration";
import {Command} from "commander";

enum CommandType {
    GetLogin,
    GetPassword,
}

interface GetLoginData {
    type: CommandType.GetLogin;
    url: string;
}

interface GetPasswordData {
    type: CommandType.GetPassword;
    url: string;
}

type CommandData = GetLoginData | GetPasswordData;

async function associate(config: Configuration, connection: KeepassXCConnection) {
    const dbHash = await connection.getDatabaseHash();

    // If we do not know this database yet or if the associate test fails, associate again
    if (!config.hasKey(dbHash) || !await connection.testAssociate(config.getKey(dbHash).id,
                                                                  config.getKey(dbHash).idKey)) {
        const associateRes = await connection.associate();

        config.saveKey(associateRes.dbHash, {
            id: associateRes.id,
            idKey: associateRes.idKey
        });
    }
}

async function main() {
    const config = new Configuration();

    await config.load();

    const program = new Command();
    program.version("1.0.0");

    let command: CommandData = null;

    program.command("get-login <url>")
           .description("Gets the login name for the specified URL.")
           .action(url => command = {
               type: CommandType.GetLogin,
               url: url
           });
    program.command("get-pw <url>")
           .description("Gets the password for the specified URL.")
           .action(url => command = {
               type: CommandType.GetPassword,
               url: url
           });

    program.parse(process.argv);

    if (!command) {
        throw new Error("No command specified!");
    }

    const connection = await KeepassXCConnection.create();
    try {
        await associate(config, connection);

        switch (command.type) {
            case CommandType.GetLogin:
            case CommandType.GetPassword: {
                const logins = await connection.getLogins(command.url);

                if (logins.length === 0) {
                    throw new Error("No entries found for URL.");
                }

                if (command.type === CommandType.GetLogin) {
                    console.log(logins[0].login);
                } else {
                    console.log(logins[0].password);
                }
                break;
            }

        }
    } finally {
        connection.disconnect();

        await config.save();
    }
}

main().then(() => {
    process.exit(0);
}).catch(err => {
    console.error(err);
    process.exit(1);
});
