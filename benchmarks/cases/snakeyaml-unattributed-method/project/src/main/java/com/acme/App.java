package com.acme;

import org.yaml.snakeyaml.Yaml;

public class App {
    String write(Object o) {
        Yaml yaml = new Yaml();
        var ctor = helper();
        ctor.load(o);
        return yaml.dump(o);
    }
}
