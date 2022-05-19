CREATE TABLE `users` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `email` VARCHAR(256) NOT NULL,
  `password` VARCHAR(256) NOT NULL,
  `enabled` TINYINT(1) NULL DEFAULT 0,
  `confirmation_token` VARCHAR(64) NULL,
  `remind_password_token` VARCHAR(64) NULL,
  `deleted` TINYINT(1) NULL DEFAULT 0,
  `last_login` DATETIME NULL,
  `registration_date` DATETIME NULL,
  `extra` VARCHAR(8000),
  PRIMARY KEY (`id`),
  UNIQUE INDEX `email_UNIQUE` (`email` ASC) VISIBLE);
