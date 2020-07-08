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

namespace Plugin\Api\Security\Voter;

use Eccube\Common\EccubeConfig;
use Eccube\Entity\Master\Authority;
use Eccube\Entity\Member;
use RuntimeException;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

class OAuthVoter implements VoterInterface
{
    /**
     * @var RequestStack
     */
    protected $requestStack;

    /**
     * @var EccubeConfig
     */
    protected $eccubeConfig;

    public function __construct(
        RequestStack $requestStack,
        EccubeConfig $eccubeConfig
    ) {
        $this->requestStack = $requestStack;
        $this->eccubeConfig = $eccubeConfig;
    }

    public function vote(TokenInterface $token, $subject, array $attributes)
    {
        $request = null;
        $path = null;

        try {
            $request = $this->requestStack->getMasterRequest();
        } catch (RuntimeException $e) {
            // requestが取得できない場合、棄権する
            return VoterInterface::ACCESS_ABSTAIN;
        }

        if (is_object($request)) {
            $path = rawurldecode($request->getPathInfo());
        }

        $Member = $token->getUser();
        if ($Member instanceof Member) {
            $adminRoute = $this->eccubeConfig->get('eccube_admin_route');

            // /api が含まれているか正規表現でURLをチェック
            if (preg_match("/^(\/{$adminRoute}\/api)/i", $path)) {
                // Member がシステム管理者でなければアクセスを拒否
                if ($Member->getAuthority()->getId() != Authority::ADMIN) {
                    return VoterInterface::ACCESS_DENIED;
                }
            }
        }

        return VoterInterface::ACCESS_GRANTED;
    }
}
