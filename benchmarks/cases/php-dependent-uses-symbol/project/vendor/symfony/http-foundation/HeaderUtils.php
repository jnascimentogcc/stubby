<?php
namespace Symfony\Component\HttpFoundation;

class HeaderUtils
{
    public static function split(string $header, string $separators): array
    {
        return preg_split('/[' . $separators . ']/', $header);
    }

    public static function unquote(string $s): string
    {
        return trim($s, '"');
    }
}
