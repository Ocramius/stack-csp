<?php
namespace KyraD\Stack;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * A Stack middleware to generate Content Security Policy (CSP) 1.0 HTTP headers.
 *
 * @author Kyra D. <kyra@existing.me>
 * @license MIT
 * @link https://github.com/KyraD/stack-csp
 */
class Csp implements HttpKernelInterface
{
    /** @var \Symfony\Component\HttpKernel\HttpKernelInterface */
    private $app;

    /** @var Csp\Config */
    private $config;

    /**
     * @param HttpKernelInterface $app
     * @param Csp\Config $cspPolicy
     */
    public function __construct(HttpKernelInterface $app, Csp\Config $cspPolicy)
    {
        $this->app = $app;
        $this->config = $cspPolicy;
    }

    /**
     * @param Request $request
     * @param int $type
     * @param bool $catch
     * @return Response
     */
    public function handle(Request $request, $type = HttpKernelInterface::MASTER_REQUEST, $catch = true)
    {
        $response = $this->app->handle($request, $type, $catch);
        $response = $this->setCspHeaders($request, $response);

        return $response;
    }

    /**
     * @param array $policy
     * @return string
     */
    private function buildHeaderValue(array $policy)
    {
        $header = '';

        foreach ($policy as $directive => $values) {
            $header .= "$directive " . implode(' ', $values) . ';';
        }

        return $header;
    }

    /**
     * @param Request $request
     * @param Response $response
     * @return Response
     */
    private function setCspHeaders(Request $request, Response $response)
    {
        $cspHeaders = $this->getCspHeaders($request->headers->get('user-agent'));

        if ($this->config->enforcePolicy) {
            $response->headers->set($cspHeaders[0], $this->buildHeaderValue($this->config->enforcePolicy));
        }

        if ($this->config->reportOnlyPolicy) {
            $response->headers->set($cspHeaders[1], $this->buildHeaderValue($this->config->reportOnlyPolicy));
        }

        return $response;
    }

    /**
     * @param $userAgent
     * @return array
     * @todo Update as vendor headers are dropped (Updated: 2013-12)
     */
    private function getCspHeaders($userAgent)
    {
        $cspHeader = ['Content-Security-Policy', 'Content-Security-Policy-Report-Only'];

        if (!preg_match('#(Firefox|Chrome|Safari)/(\d+)|(MSIE) (1\d)#', $userAgent, $arr)) {
            return $cspHeader;
        }

        if (('Chrome' === $arr[1] && 14 <= $arr[2] && 24 >= $arr[2]) || ('Safari' === $arr[1] && 6 <= $arr[2])) {

            /** Chrome 14 to 24, Safari 6+ */
            return ['X-WebKit-CSP', 'X-WebKit-CSP-Report-Only'];
        }

        if (('Firefox' === $arr[1] && 4 <= $arr[2] && 22 >= $arr[2]) || ('MSIE' === $arr[1])) {

            /** Firefox 4 to 22, IE 10+ */
            return ['X-Content-Security-Policy', 'X-Content-Security-Policy-Report-Only'];
        }

        return $cspHeader;
    }
}
