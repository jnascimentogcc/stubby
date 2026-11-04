<?php
namespace App;

use Symfony\Component\HttpFoundation\Request;

class Handler
{
    public function handle()
    {
        return Request::createFromGlobals();
    }
}
