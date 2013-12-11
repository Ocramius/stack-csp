<?php
/*
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This software consists of voluntary contributions made by many individuals
 * and is licensed under the MIT license.
 */

namespace KyraDTest\Stack;

use KyraD\Stack\Csp;
use KyraD\Stack\Csp\Config;
use PHPUnit_Framework_TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * A Stack middleware to generate Content Security Policy (CSP) 1.0 HTTP headers.
 *
 * @author Marco Pivetta <ocramius@gmail.com>
 * @copyright 2013 Kyra D.
 * @license MIT
 * @link https://github.com/KyraD/stack-csp
 * @package KyraD\Stack\Csp
 * @version 0.1.0
 *
 * @covers \KyraD\Stack\Csp
 */
class CspTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var \Symfony\Component\HttpKernel\HttpKernelInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    private $app;

    /**
     * @var Config
     */
    private $config;

    /**
     * @var Csp
     */
    private $csp;

    /**
     * @var
     */
    private $request;

    /**
     * {@inheritDoc}
     */
    public function setUp()
    {
        $this->app    = $this->getMock('Symfony\Component\HttpKernel\HttpKernelInterface');
        $this->config = new Config();
        $this->csp    = new Csp($this->app, $this->config);
    }

    public function testSimpleHandle()
    {
        $request  = $this->buildRequest();
        $response = $this->buildResponse();

        $this
            ->app
            ->expects($this->once())
            ->method('handle')
            ->with($request, 123, false)
            ->will($this->returnValue($response));

        $this->assertSame(
            $response,
            $this->csp->handle($request, 123, false),
            'The request dispatching is delegated to the application with correct parameters'
        );
    }

    public function testSetsEnforcePolicyHeader()
    {
        $request  = $this->buildRequest();
        $response = $this->buildResponse();

        $this->config->enforcePolicy = ['foo' => ['bar', 'baz']];
        $this->app->expects($this->any())->method('handle')->will($this->returnValue($response));
        $request
            ->headers
            ->expects($this->any())
            ->method('get')
            ->with('user-agent')
            ->will($this->returnValue('Firefox 123'));


        $response->headers->expects($this->once())->method('set')->with('Content-Security-Policy', 'foo bar baz;');

        $this->csp->handle($request);
    }

    /**
     * Since Symfony's Http Request object is full of... public properties
     * we need to make a real one instead of a mock
     *
     * @return Request
     */
    private function buildRequest()
    {
        $request          = new Request();
        $headers          = $this->getMock('Symfony\Component\HttpFoundation\HeaderBag');
        $request->headers = $headers;

        return $request;
    }

    /**
     * Since Symfony's Http Response object is full of... public properties
     * we need to make a real one instead of a mock
     *
     * @return Response
     */
    private function buildResponse()
    {
        $response          = new Response();
        $headers           = $this->getMock('Symfony\Component\HttpFoundation\HeaderBag');
        $response->headers = $headers;

        return $response;
    }
}
