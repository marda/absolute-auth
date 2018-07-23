<?php

namespace Absolute\Module\Auth\Presenter;

use Nette\Http\Response;
use Nette\Application\Responses\JsonResponse;

class DefaultPresenter extends AuthBasePresenter
{

    /** @var \Absolute\Module\User\Manager\UserManager @inject */
    public $userManager;

    public function startup()
    {
        parent::startup();
    }

    public function renderDefault()
    {

        switch ($this->httpRequest->getMethod()) {
            case 'POST':                               
                try
                {
                    $this->user->login($this->httpRequest->getPost('username'), $this->httpRequest->getPost('password'));
                    $this->user->setExpiration('+ 14 days', FALSE);
                    $user = $this->userManager->getByUsername($this->httpRequest->getPost('username'));                   
                    $this->jsonResponse->payload = $user->toJson();
                    $this->httpResponse->setCode(Response::S200_OK);
                } catch (\Nette\Security\AuthenticationException $e)
                {
                    $this->jsonResponse->payload = ['message' => $e->getMessage()];
                    $this->httpResponse->setCode(Response::S401_UNAUTHORIZED);
                }
                break;
            case 'OPTIONS':
                $this->httpResponse->setCode(Response::S200_OK);
            default:
                break;
        }
        $this->sendResponse(new JsonResponse(
            $this->jsonResponse->toJson(), "application/json;charset=utf-8"
        ));
    }

}
