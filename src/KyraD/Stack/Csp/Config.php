<?php
namespace KyraD\Stack\Csp;

use Symfony\Component\HttpFoundation\Request;

/**
 * Manages CSP policy arrays
 *
 * @author Kyra D. <kyra@existing.me>
 * @copyright 2013 Kyra D.
 * @license MIT
 * @link https://github.com/KyraD/stack-csp
 * @package KyraD\Stack\Csp
 * @version 0.1.0
 */
class Config
{
    /** @var array */
    public $enforcePolicy = [];

    /** @var array */
    public $reportOnlyPolicy = [];

    /**
     * @param array $policy
     */
    public function __construct(array $policy = [])
    {
        if (isset($policy['enforce'])) {
            $this->enforcePolicy = $policy['enforce'];
        }

        if (isset($policy['report-only'])) {
            $this->reportOnlyPolicy = $policy['report-only'];
        }

        return $this;
    }

    /**
     * @param Request $request
     */
    public function compilePolicy(Request $request)
    {
        try {

            $this->processRoutePolicies($request);

            array_walk($this->enforcePolicy, [new Validate, 'parsePolicy']);
            array_walk($this->reportOnlyPolicy, [new Validate, 'parsePolicy']);

        } catch (\UnexpectedValueException $e) {
            exit('Unexpected value: ' . $e->getMessage());
        }
    }

    /**
     * @param Request $request
     */
    private function processRoutePolicies(Request $request)
    {
        if ($request->attributes->get('clearCspPolicy')) {
            $this->clearCspPolicy($request->attributes->get('clearCspPolicy'));
        }

        if (is_array($request->attributes->get('removeFromCspPolicy'))) {
            $policy = $request->attributes->get('removeFromCspPolicy');
            array_walk($policy, [$this, 'removeFromCspPolicy']);
        }

        if (is_array($request->attributes->get('addToCspPolicy'))) {
            $policy = $request->attributes->get('addToCspPolicy');
            array_walk($policy, [$this, 'addToCspPolicy']);
        }
    }

    /**
     * @param $policyType
     * @throws \UnexpectedValueException
     */
    private function clearCspPolicy($policyType)
    {
        if ('enforce' === $policyType) {
            $this->enforcePolicy = [];
            return;
        }

        if ('report-only' === $policyType) {
            $this->reportOnlyPolicy = [];
            return;
        }

        if ('all' === $policyType || 'both' === $policyType) {
            $this->enforcePolicy = [];
            $this->reportOnlyPolicy = [];
            return;
        }

        throw new \UnexpectedValueException("'$policyType' is not a valid clear policy option");
    }

    /**
     * @param array $addPolicy
     * @param $policyType
     * @throws \UnexpectedValueException
     */
    private function addToCspPolicy(array $addPolicy, $policyType)
    {
        if ('enforce' === $policyType) {
            $this->enforcePolicy = array_merge_recursive($this->enforcePolicy, $addPolicy);
            return;
        }

        if ('report-only' === $policyType) {
            $this->reportOnlyPolicy = array_merge_recursive($this->reportOnlyPolicy, $addPolicy);
            return;
        }

        throw new \UnexpectedValueException("'addToCspPolicy' supplied an invalid policy type of '$policyType'");
    }

    /**
     * @param array $removePolicy
     * @param $policyType
     * @throws \UnexpectedValueException
     */
    private function removeFromCspPolicy(array $removePolicy, $policyType)
    {
        if ('enforce' !== $policyType && 'report-only' !== $policyType) {
            throw new \UnexpectedValueException("invalid policy type of '$policyType' for 'removeFromCspPolicy'");
        }

        $this->applyPolicyDiff($removePolicy, 'enforcePolicy');
        $this->applyPolicyDiff($removePolicy, 'reportOnlyPolicy');
    }

    /**
     * @param array $removePolicy
     * @param $policyType
     */
    private function applyPolicyDiff(array $removePolicy, $policyType)
    {
        foreach ($removePolicy as $key => $values) {

            if (isset($this->{$policyType}[$key])) {

                $arrayDiff = array_diff((array)$this->{$policyType}[$key], (array)$values);

                if (empty($arrayDiff)) {
                    unset($this->{$policyType}[$key]);
                    continue;
                }

                $this->{$policyType}[$key] = $arrayDiff;
            }
        }
    }
}
