<?php
namespace Symfony\Component\HttpFoundation;

class HeaderBag
{
    public function __construct(private array $headers = [])
    {
    }

    public function getCacheControlDirectives(): array
    {
        return HeaderUtils::split($this->headers['cache-control'] ?? '', ',');
    }
}
