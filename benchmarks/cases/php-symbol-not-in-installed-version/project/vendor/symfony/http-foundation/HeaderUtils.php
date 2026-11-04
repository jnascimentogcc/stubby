<?php
namespace Symfony\Component\HttpFoundation;

class HeaderUtils
{
    public static function unquote(string $s): string
    {
        return trim($s, '"');
    }
}
