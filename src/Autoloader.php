<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-logimail-engine (bin/lh-mail)
// Module:        Logihertz\LogiMail\Autoloader
// Role:          Zero-Dependency PSR-4 Class Autoloader
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

namespace Logihertz\LogiMail;

/**
 * PSR-4 compliant zero-dependency class autoloader for the Logihertz\LogiMail namespace.
 */
final class Autoloader
{
    private const string PREFIX = 'Logihertz\\LogiMail\\';
    private static bool $registered = false;

    /**
     * Register the autoloader with SPL.
     */
    public static function register(): void
    {
        if (self::$registered) {
            return;
        }

        spl_autoload_register(self::loadClass(...));
        self::$registered = true;
    }

    /**
     * Unregister the autoloader from SPL.
     */
    public static function unregister(): void
    {
        if (!self::$registered) {
            return;
        }

        spl_autoload_unregister(self::loadClass(...));
        self::$registered = false;
    }

    /**
     * Load the requested class file if it belongs to this namespace.
     *
     * @param string $class Fully qualified class name.
     * @return bool True if loaded successfully, false otherwise.
     */
    public static function loadClass(string $class): bool
    {
        if (!str_starts_with($class, self::PREFIX)) {
            return false;
        }

        $relativeClass = substr($class, strlen(self::PREFIX));
        $filePath = __DIR__ . '/' . str_replace('\\', '/', $relativeClass) . '.php';

        if (is_file($filePath)) {
            require_once $filePath;
            return true;
        }

        return false;
    }
}
