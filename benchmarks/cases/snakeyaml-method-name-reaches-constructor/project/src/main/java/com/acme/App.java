package com.acme;

import org.yaml.snakeyaml.Yaml;

public class App {
    Object read(String s) {
        Yaml yaml = new Yaml();
        return yaml.load(s);
    }
}
