<?php
namespace Symfony\Component\HttpFoundation;

class Response
{
    public function __construct(private string $content = '', private int $status = 200)
    {
    }

    public function getContent(): string
    {
        return $this->content;
    }

    public function send(): static
    {
        echo $this->content;
        return $this;
    }
}
