<?php
namespace App;

use Symfony\Component\HttpFoundation\Response;

class Handler
{
    public function handle()
    {
        return new Response('ok');
    }
}
