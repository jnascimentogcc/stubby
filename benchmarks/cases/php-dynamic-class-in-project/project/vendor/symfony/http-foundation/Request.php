<?php
namespace Symfony\Component\HttpFoundation;

class Request
{
    public $headers;

    public static function createFromGlobals(): static
    {
        $request = new static();
        $request->headers = new HeaderBag($_SERVER);
        return $request;
    }
}
