package com.acme;


public class App {
    Object make(String name) throws Exception {
        return Class.forName(name).getDeclaredConstructor().newInstance();
    }
}
