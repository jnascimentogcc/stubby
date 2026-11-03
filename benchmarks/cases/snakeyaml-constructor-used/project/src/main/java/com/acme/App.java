package com.acme;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

public class App {
    Object read(String s) {
        return new Yaml(new Constructor(Config.class)).load(s);
    }
}
