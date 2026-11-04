<?php
namespace Acme\Lib;

use Symfony\Component\HttpFoundation\Request;

class Page
{
    public function current()
    {
        return Request::createFromGlobals();
    }
}
