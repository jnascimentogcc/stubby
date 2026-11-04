<?php
namespace Acme\Lib;

use Symfony\Component\HttpFoundation\Response;

class Page
{
    public function render(): Response
    {
        return new Response('page');
    }
}
