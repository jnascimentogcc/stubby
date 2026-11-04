<?php
namespace App;

use Symfony\Component\HttpFoundation\Response;

class Handler
{
    public function make(string $class)
    {
        return new $class();
    }

    public function ok()
    {
        return new Response('ok');
    }
}
