<?php
namespace App;

use Symfony\Component\HttpFoundation\HeaderUtils;

class Handler
{
    public function parse(string $h): array
    {
        return HeaderUtils::split($h, ',');
    }
}
