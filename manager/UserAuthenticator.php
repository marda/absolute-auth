<?php


namespace Absolute\Module\Auth\Manager;

use Nette\Security\IAuthenticator;
use Nette\Database\Context;
use Nette\Security\AuthenticationException;
use Nette\Security\Identity;

use Absolute\Module\User\Manager\UserManager;
use Absolute\Module\User\Manager\UserCRUDManager;

class UserAuthenticator implements IAuthenticator
{
	/** @var Nette\Database\Context */
	private $database;

	/** @var Absolute\Module\User\Manager\UserManager */
	private $userManager;

	/** @var Absolute\Module\User\Manager\UserCRUDManager */
	private $userCRUDManager;

	public function __construct(
		Context $database, 
		UserManager $userManager,
		UserCRUDManager $userCRUDManager
	)
	{
		$this->database = $database;
		$this->userManager = $userManager;
		$this->userCRUDManager = $userCRUDManager;
	}

	/**
	 * Performs an authentication.
	 * @return Nette\Security\Identity
	 * @throws Nette\Security\AuthenticationException
	 */
	public function authenticate(array $credentials)
	{
		list($username, $password) = $credentials;

		$row = $this->database->table('user')->where('username', $username)->fetch();
		
		if (!$row) 
		{
			throw new AuthenticationException('Username does not exists.', self::IDENTITY_NOT_FOUND);
		} 
		// not password or generated password does not match
		elseif ($row->password !== sha1($password) && $row->password_generated !== sha1($password)) 
		{
			throw new AuthenticationException('Password is invalid.', self::INVALID_CREDENTIAL);
		}

		// password macht original password, so we clear generated password
		if ($row->password === sha1($password) && $row->password_generated) 
		{
			$this->database->table('user')->where('username', $username)->update(array(
				'password_generated' => "",
			));			
		}

		// password match generated password so we chaneg password for user
		if ($row->password_generated === sha1($password)) 
		{
			$this->userCRUDManager->changePassword($password, $row->id);	
		}

		$user = $this->userManager->getById($row->id);
		return new Identity($row->id, $row->role, array("user" => $user));
	}
}
