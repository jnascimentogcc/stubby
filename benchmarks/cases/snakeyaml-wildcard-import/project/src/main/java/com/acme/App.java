package com.acme;

import org.yaml.snakeyaml.constructor.*;

public class App {
    String write(Object o) {
        return new org.yaml.snakeyaml.Yaml().dump(o);
    }
}
