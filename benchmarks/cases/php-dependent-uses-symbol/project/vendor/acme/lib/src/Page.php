<?php
namespace Acme\Lib;

use Symfony\Component\HttpFoundation\HeaderUtils;

class Page
{
    public function parts(string $h): array
    {
        return HeaderUtils::split($h, ',');
    }
}
