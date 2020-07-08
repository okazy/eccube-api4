<?php

/*
 * This file is part of EC-CUBE
 *
 * Copyright(c) EC-CUBE CO.,LTD. All Rights Reserved.
 *
 * http://www.ec-cube.co.jp/
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Plugin\Api\Tests\Security\Voter;

use Eccube\Common\EccubeConfig;
use Eccube\Entity\Master\Authority;
use Eccube\Tests\EccubeTestCase;
use Plugin\Api\Security\Voter\OAuthVoter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

class OAuthVoterTest extends EccubeTestCase
{
    /**
     * @var EccubeConfig
     */
    protected $eccubeConfig;

    public function setUp()
    {
        parent::setUp();
        $this->eccubeConfig = $this->container->get(EccubeConfig::class);
    }

    /**
     * @dataProvider voteProvider
     *
     * @param $authority
     * @param $accessUrl
     * @param $expected
     */
    public function testVote($authority, $accessUrl, $expected)
    {
        $request = $this->createMock(Request::class);
        $request->method('getPathInfo')->willReturn($accessUrl);

        $requestStack = $this->createMock(RequestStack::class);
        $requestStack->method('getMasterRequest')->willReturn($request);

        $voter = new OAuthVoter($requestStack, $this->eccubeConfig);

        $Member = $this->createMember();

        /** @var Authority $Authority */
        $Authority = $this->entityManager->find(Authority::class, $authority);
        $Member->setAuthority($Authority);

        $token = $this->createMock(TokenInterface::class);
        $token->method('getUser')->willReturn($Member);

        self::assertEquals($expected, $voter->vote($token, null, []));
    }

    public function voteProvider()
    {
        return [
            [Authority::ADMIN, '/admin/api', VoterInterface::ACCESS_GRANTED],
            [Authority::ADMIN, '/admin/api/config', VoterInterface::ACCESS_GRANTED],
            [Authority::ADMIN, '/', VoterInterface::ACCESS_GRANTED],
            [Authority::ADMIN, '/cart', VoterInterface::ACCESS_GRANTED],
            [Authority::ADMIN, '/api', VoterInterface::ACCESS_GRANTED],
            [Authority::ADMIN, '/admin', VoterInterface::ACCESS_GRANTED],
            [Authority::ADMIN, '/admin/product', VoterInterface::ACCESS_GRANTED],
            [Authority::OWNER, '/admin/api', VoterInterface::ACCESS_DENIED],
            [Authority::OWNER, '/admin/api/config', VoterInterface::ACCESS_DENIED],
            [Authority::OWNER, '/', VoterInterface::ACCESS_GRANTED],
            [Authority::OWNER, '/cart', VoterInterface::ACCESS_GRANTED],
            [Authority::OWNER, '/api', VoterInterface::ACCESS_GRANTED],
            [Authority::OWNER, '/admin', VoterInterface::ACCESS_GRANTED],
            [Authority::OWNER, '/admin/product', VoterInterface::ACCESS_GRANTED],
        ];
    }
}
