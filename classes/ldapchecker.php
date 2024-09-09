<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Sub-plugin ldapchecker.
 *
 * @package   userstatus_ldapchecker
 * @copyright 2016/17 N. Herrmann
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace userstatus_ldapchecker;

use core\session\exception;
use tool_cleanupusers\archiveduser;
use tool_cleanupusers\userstatusinterface;
use tool_cleanupusers\userstatuschecker;




defined('MOODLE_INTERNAL') || die;

/**
 * Class that checks the status of different users depending on the time they have not signed in for.
 *
 * @package    userstatus_ldapchecker
 * @copyright  2016/17 N Herrmann
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

class ldapchecker extends userstatuschecker { // implements userstatusinterface {

    /** @var int seconds until a user should be deleted */
    private $timedelete;

    /** @var array lookuptable for ldap users */
    private $lookup = array();

    private $config;

    private $testing = false;

    private function init() {
        // Only connect to LDAP if we are not in testing case
        if ($this->testing === false) {

            $ldap = ldap_connect($this->config->host_url) or die("Could not connect to $this->config->host_url");

            $bind = ldap_bind($ldap, $this->config->bind_dn, $this->config->bind_pw); // returns 1 if correct

            if($bind) {
                $this->log("ldap_bind successful");

                $contexts = $this->config->contexts;

                $uid = $this->config->ldap_username_attribute;
                $attributes = [$uid];
                $filter = $this->config->search_filter; // '(cn=*)';
                $search = ldap_search($ldap, $contexts, $filter, $attributes) or die("Error in search Query: " . ldap_error($ldap));
                $result = ldap_get_entries($ldap, $search);

                foreach ($result as $user) {
                    if(isset($user[$uid])) {
                        foreach ($user[$uid] as $cn) {
                            $this->lookup[$cn] = true;
                        }
                    }
                }

                $this->log("ldap server sent " . count($this->lookup) . " users");

            } else {
                $this->log("ldap_bind failed");
                // fatal error!
                throw new exception("cannot connect to LDAP server");
            }
        }

    }
    /**
     * This constructor sets timesuspend and timedelete from days to seconds.
     * @throws \dml_exception
     */
    public function __construct($testing = false) {
        // debugging("ldapchecker::__construct");
        parent::__construct($testing);

        $this->config = get_config('userstatus_ldapchecker');

        // Calculates days to seconds.
        $this->timedelete = $this->config->deletetime * 86400;
        $this->testing = $testing;
    }


    private function is_initialised() {
        if (count($this->lookup) == 0) {
            $this->init();
            if (count($this->lookup) == 0) {
                return false;
            }
        }
        return true;
    }

    public function condition_sql() : array {
        return ["" , null];
    }

    public function shall_suspend($user) : bool {
        // check initialisation state (todo: should not be checked for every user!)
        if (!$this->is_initialised()) {
            return false;
        }
        return (array_key_exists($user->username, $this->lookup));
    }


    /**
     * All users who are not suspended and not deleted are selected. If a user did not sign in for the hitherto
     * determined suspendtime he/she will be returned.
     * Users not signed in for the hitherto determined suspendtime, do not show up in the ldap lookuptable.
     * The array includes merely the necessary information which comprises the userid, lastaccess, suspended, deleted
     * and the username.
     *
     * @return array of users to suspend
     * @throws \dml_exception
     */
    /*
    public function get_to_suspend() {
        global $DB;
        if (count($this->lookup) == 0) {
            $this->init();
            if (count($this->lookup) == 0) {
                $this->log("no users from LDAP found => do not evaluate users to suspend");
                return [];
            }
        }

        $select = "auth='" . $this->config->auth_method . "' AND deleted=0 AND suspended=0";
        $this->log("[get_to_suspend] " . $select);
        $users = $DB->get_records_select('user', $select, null, '',
            "id, suspended, lastaccess, username, deleted");
        $this->log("[get_to_suspend] found " . count($users) . " users in user table to check");

        $tosuspend = [];

        foreach ($users as $key => $user) {
            if (!is_siteadmin($user) && !array_key_exists($user->username, $this->lookup)) {
                $suspenduser = new archiveduser(
                    $user->id,
                    $user->suspended,
                    $user->lastaccess,
                    $user->username,
                    $user->deleted);
                $tosuspend[$key] = $suspenduser;
                $this->log("[get_to_suspend] " . $user->username . " marked");
            }
        }
        $this->log("[get_to_suspend] marked " . count($tosuspend) . " users");

        return $tosuspend;
    }*/

    /**
     * All users who never logged in will be returned in the array.
     * The array includes merely the necessary information which comprises the userid, lastaccess, suspended, deleted
     * and the username.
     *
     * @return array of users who never logged in
     * @throws \dml_exception
     */
    /*
    public function get_never_logged_in() {
        global $DB;
        $arrayofuser = $DB->get_records_sql(
            "SELECT u.id, u.suspended, u.lastaccess, u.username, u.deleted
                FROM {user} u
                LEFT JOIN {tool_cleanupusers} tc ON u.id = tc.id
                WHERE u.auth = '" . $this->config->auth_method . "'
                    AND u.lastaccess = 0
                    AND u.deleted = 0
                    AND tc.id IS NULL"
        );

        $neverloggedin = [];
        foreach ($arrayofuser as $key => $user) {
            $informationuser = new archiveduser(
                $user->id,
                $user->suspended,
                $user->lastaccess,
                $user->username,
                $user->deleted);
            $neverloggedin[$key] = $informationuser;
        }

        return $neverloggedin;
    }
*/
    /**
     * All users who should be deleted will be returned in the array.
     * The array includes merely the necessary information which comprises the userid, lastaccess, suspended, deleted
     * and the username.
     * The function checks the user table and the tool_cleanupusers_archive table. Therefore, users who are suspended by
     * the tool_cleanupusers plugin and users who are suspended manually are screened.
     *
     * @return array of users who should be deleted.
     * @throws \dml_exception
     */
    public function get_to_delete() {
        global $DB;

        if (count($this->lookup) == 0) {
            $this->init();
            if (count($this->lookup) == 0) {
                $this->log("no users from LDAP found => do not evaluate users to delete");
                return [];
            }
        }

        $users = $DB->get_records_sql(
            "SELECT tca.id, tca.suspended, tca.lastaccess, tca.username, tca.deleted
                FROM {user} u
                JOIN {tool_cleanupusers} tc ON u.id = tc.id
                JOIN {tool_cleanupusers_archive} tca ON u.id = tca.id
                WHERE u.auth = '" . $this->config->auth_method . "'
                    AND u.suspended = 1
                    AND u.deleted = 0
                    AND tc.timestamp < :timelimit",
            [
                'timelimit'  => time() - $this->timedelete,
            ]
        );
        $todelete = [];

        foreach ($users as $key => $user) {
            if (!is_siteadmin($user) && !array_key_exists($user->username, $this->lookup)) {
                $deleteuser = new archiveduser(
                    $user->id,
                    $user->suspended,
                    $user->lastaccess,
                    $user->username,
                    $user->deleted
                );
                $todelete[$key] = $deleteuser;
                $this->log("[get_to_delete] " . $user->username . " marked");
            }
        }
        $this->log("[get_to_delete] marked " . count($todelete) . " users");

        return $todelete;
    }

    /**
     * All users that should be reactivated will be returned.
     *
     * @return array of objects
     * @throws \dml_exception
     * @throws \dml_exception
     */
    public function get_to_reactivate() {
        global $DB;
        if (count($this->lookup) == 0) {
            $this->init();
            if (count($this->lookup) == 0) {
                $this->log("no users from LDAP found => do not evaluate users to reactivate");
                return [];
            }
      }

        // Only users who are currently suspended are relevant.
        $users = $DB->get_records_sql(
            "SELECT tca.id, tca.suspended, tca.lastaccess, tca.username, tca.deleted
                FROM {user} u
                JOIN {tool_cleanupusers} tc ON u.id = tc.id
                JOIN {tool_cleanupusers_archive} tca ON u.id = tca.id
                WHERE u.auth = '" . $this->config->auth_method . "'
                    AND u.suspended = 1
                    AND u.deleted = 0
                    AND tca.username NOT IN
                        (SELECT username FROM {user} WHERE username IS NOT NULL)"
        );
        $toactivate = [];

        // $config = get_config('userstatus_ldapchecker');

        foreach ($users as $key => $user) {
            if (!is_siteadmin($user) && array_key_exists($user->username, $this->lookup)) {
                $activateuser = new archiveduser(
                    $user->id,
                    $user->suspended,
                    $user->lastaccess,
                    $user->username,
                    $user->deleted
                );
                $toactivate[$key] = $activateuser;
                $this->log("[get_to_reactivate] " . $user->username . " marked");
            }
        }
        $this->log("[get_to_reactivate] marked " . count($toactivate) . " users");

        return $toactivate;
    }

    public function fill_ldap_response_for_testing($dummy_ldap) {
        $this->lookup = $dummy_ldap;
    }

    /**
     * returns the authentication method for all users being handled by this plugin
     * @return string
     */
    public function get_authentication_method() :string {
        return $this->config->auth_method;
    }

}
