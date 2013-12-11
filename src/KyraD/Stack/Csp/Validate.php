<?php
namespace KyraD\Stack\Csp;

/**
 * Validates CSP directives and values
 *
 * @author Kyra D. <kyra@existing.me>
 * @license MIT
 * @link https://github.com/KyraD/stack-csp
 * @todo Update to CSP 1.1 when no longer a draft
 */
class Validate
{
    /**
     * @var array
     */
    private $directives = [
        'report-uri' => [],
        'sandbox' => [
            'allow-forms',
            'allow-same-origin',
            'allow-scripts',
            'allow-top-navigation'
        ],
        'connect-src' => ['none', 'self'],
        'default-src' => ['none', 'self'],
        'font-src' => ['none', 'self'],
        'frame-src' => ['none', 'self'],
        'img-src' => ['none', 'self'],
        'media-src' => ['none', 'self'],
        'object-src' => ['none', 'self'],
        'script-src' => [
            'none',
            'self',
            'unsafe-eval',
            'unsafe-inline'
        ],
        'style-src' => [
            'none',
            'self',
            'unsafe-inline'
        ]
    ];

    /**
     * @param $values
     * @param $directive
     */
    public function parsePolicy(&$values, $directive)
    {
        /** pass by reference to apply this change to policy as well */
        $values = array_unique((array)$values);

        if ('report-uri' === $directive) {
            array_walk($values, [$this, 'isValidReportUri']);
            return;
        }

        if ('sandbox' === $directive) {
            array_walk($values, [$this, 'isValidSandboxKeyword']);
            return;
        }

        $this->isValidDirectiveName($directive);

        if (1 < count($values)) {
            $this->isValidNoneSrcList($values, $directive);
            $this->isValidWildcardSrcList($values, $directive);
        }

        foreach ($values as &$value) {

            $this->isValidSrcValue($value, $directive);

            if (in_array($value, $this->directives[$directive])) {

                /** pass by reference to quote value in policy */
                $value = "'$value'";
            }
        }
    }

    /**
     * @param $values
     * @param $directive
     * @throws \UnexpectedValueException
     */
    private function isValidNoneSrcList(array $values, $directive)
    {
        if (in_array('none', $values) && in_array('none', $this->directives[$directive])) {
            throw new \UnexpectedValueException("'none' DENIES ALL for '$directive' directive, but exceptions are set");
        }
    }

    /**
     * @param array $values
     * @param $directive
     * @throws \UnexpectedValueException
     */
    private function isValidWildcardSrcList(array $values, $directive)
    {
        if (in_array('*', $values)) {
            throw new \UnexpectedValueException("'*' ALLOWS ALL for '$directive' directive, but exceptions are set");
        }
    }

    /**
     * @param $directive
     * @throws \UnexpectedValueException
     */
    private function isValidDirectiveName($directive)
    {
        if (!array_key_exists($directive, $this->directives)) {
            throw new \UnexpectedValueException("'$directive' is an invalid CSP 1.0 directive");
        }
    }

    /**
     * @param $value
     * @throws \UnexpectedValueException
     */
    private function isValidSandboxKeyword($value)
    {
        if (!in_array($value, $this->directives['sandbox'])) {
            throw new \UnexpectedValueException("'$value' is an invalid CSP 1.0 'sandbox' keyword");
        }
    }

    /**
     * @param $value
     * @param $directive
     * @throws \UnexpectedValueException
     */
    private function isValidSrcValue($value, $directive)
    {
        /** @author HamZa <https://github.com/Hamz-a> */
        $regex = '~
            (?(DEFINE)
               (?<ipv4>                                         # IPv4 address / domain name (with sub-domain wildcards)
                  (?=\S*?(?:\.|localhost))                      # make sure there is at least one dot or localhost
                  (?:\*\.)?                                     # wildcard only allowed at start
                  (?:[a-z\d-][a-z\d.-]*|%[a-f\d]{2}+)
               )
               (?<ipv6>\[(?:[a-f\d]{0,4}:)*(?:[a-f\d]{0,4})\])  # IPv6 address
               (?<port>:\d+)                                    # port number
               (?<dataScheme>                                   # data: scheme
                  (?<!.)data:(?!.)
               )
               (?<wildcard>                                     # wildcard
                  (?<!.)\*(?!.)
               )
               (?<httpScheme>https?://)
               (?<url>                                          # host
                  (?&httpScheme)?
                  (?:(?&ipv4)|(?&ipv6))
                  (?&port)?                                     # optional port number
               )
            )

            ^(?:(?&url)|(?&dataScheme)|(?&wildcard))$           # regex
        ~ix';

        if (!in_array($value, $this->directives[$directive]) && !preg_match($regex, $value)) {
            throw new \UnexpectedValueException("'$value' is an invalid CSP 1.0 '$directive' value");
        }
    }

    /**
     * {@internal Don't use FILTER_VALIDATE_URL which is RFC 2396, or parse_url() which allows practically anything.
     * We do not allow HTTP login via URI as such sensitive information should never be sent to client.
     * We restrict to HTTP schemes only, allow absolute and relative URIs}}
     * @param $uri
     * @throws \UnexpectedValueException
     */
    private function isValidReportUri($uri)
    {
        /** RFC 3986 */
        $regex = '~
            (?(DEFINE)
               (?<ipv4>                                         # IPv4 address / domain name
                  (?=\S*?(?:\.|localhost))                      # make sure there is at least one dot or localhost
                  (?:[a-z\d-][a-z\d.-]*|%[a-f\d]{2}+)
               )
               (?<ipv6>\[(?:[a-f\d]{0,4}:)*(?:[a-f\d]{0,4})\])  # IPv6 address
               (?<port>:\d+)                                    # port number
               (?<httpScheme>https?://)
               (?<queryPath>/                                   # path and query
                    (?:[\w!#$&\'()*+,./:;=?@\[\]\~-]
                    |
                    %[a-f\d]{2})*                               # encoded chars
               )
               (?<url>                                          # host
                  (?&httpScheme)?
                  (?:(?&ipv4)|(?&ipv6))
                  (?&port)?                                     # optional port number
                  (?&queryPath)?                                # optional path and query
               )
            )

            ^(?:(?&url)|(?&queryPath))$                         # regex
        ~ix';

        if (!preg_match($regex, $uri)) {
            throw new \UnexpectedValueException("'$uri' is an invalid 'report-uri' value, must be of type RFC 3986");
        }
    }
}
