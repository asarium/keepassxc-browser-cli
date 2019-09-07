import * as path from "path";
import {promises as fsp} from "fs";

function getConfigFile() {
    let data_home = process.env.XDG_CONFIG_HOME;
    if (!data_home) {
        data_home = path.join(process.env.HOME, ".config");
    }

    return path.join(data_home, "keepassxc-node-cli", "config.json");
}

async function fileExists(path: string): Promise<boolean> {
    try {
        const stats = await fsp.lstat(path);

        return stats.isFile();
    } catch (Error) {
        // Path does not exist
        return false;
    }
}

interface DbKey {
    id: string;
    idKey: string;
}

interface ConfigData {
    version: number;
    dbKeys: { [dbHash: string]: DbKey };
}

export class Configuration {
    private readonly _configFile: string;

    private _keys: { [dbHash: string]: DbKey };

    constructor() {
        this._configFile = getConfigFile();
    }

    public async load() {
        if (!await fileExists(this._configFile)) {
            this._keys = {};
            return;
        }

        const configData = await fsp.readFile(this._configFile, {
            encoding: "utf-8"
        });

        const config: ConfigData = JSON.parse(configData);

        this._keys = config.dbKeys;
    }

    public async save() {
        const configData: ConfigData = {
            version: 1,
            dbKeys: this._keys,
        };

        await fsp.mkdir(path.dirname(this._configFile), {recursive: true});

        await fsp.writeFile(this._configFile, JSON.stringify(configData), {
            encoding: "utf-8"
        });
    }

    public hasKey(dbHash: string): boolean {
        return dbHash in this._keys;
    }

    public getKey(dbHash: string): DbKey {
        return this._keys[dbHash];
    }

    public saveKey(dbHash: string, key: DbKey) {
        this._keys[dbHash] = key;
    }
}