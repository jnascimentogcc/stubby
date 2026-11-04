<?php
namespace App;

use Symfony\Component\HttpFoundation\Response;

class Handler
{
    public function handle(Response $r)
    {
        return $r->send();
    }
}
