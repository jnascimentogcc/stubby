<?php
namespace App;

use Acme\Lib\Page;

class Handler
{
    public function show()
    {
        return (new Page())->current();
    }
}
