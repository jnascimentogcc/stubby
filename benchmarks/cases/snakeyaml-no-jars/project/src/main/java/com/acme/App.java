package com.acme;

import org.yaml.snakeyaml.Yaml;

public class App {
    String write(Object o) {
        return new Yaml().dump(o);
    }
}
