package actions

import (
	"fmt"

	"github.com/bscott/golangflow/models"
	"github.com/gobuffalo/buffalo"
	"github.com/gobuffalo/envy"
	"github.com/labstack/gommon/log"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/pop"
	"github.com/markbates/pop/nulls"
	"github.com/pkg/errors"
)

func init() {
	gothic.Store = App().SessionStore
	ghKey, err := envy.MustGet("GITHUB_KEY")
	if err != nil {
		log.Info("No github key set.  To enable logins set a GITHUB_KEY environment variable.")
		log.Info("See https://developer.github.com/apps/building-oauth-apps/creating-an-oauth-app/ for details on how to obtain a key")
	}
	ghSecret, err := envy.MustGet("GITHUB_SECRET")
	if err != nil {
		log.Info("No github secret set.  To enable logins set a GITHUB_SECRET environment variable.")
	}
	goth.UseProviders(
		github.New(ghKey, ghSecret, fmt.Sprintf("%s%s", App().Host, "/auth/github/callback")),
	)
}

// AuthCallback handles Provider callbacks
func AuthCallback(c buffalo.Context) error {
	user, err := gothic.CompleteUserAuth(c.Response(), c.Request())
	if err != nil {
		return errors.WithStack(err)
	}
	// Do something with the user, maybe register them/sign them in
	// Adding the userID to the session to remember the logged in user
	tx := c.Value("tx").(*pop.Connection)

	// To find the User the parameter user_id is used.
	q := tx.Where("provider = ? and provider_userid = ?", user.Provider, user.UserID)
	exists, err := q.Exists("users")

	if err != nil {
		return errors.WithStack(err)
	}

	u := &models.User{}

	if exists {
		err := q.First(u)
		if err != nil {
			return errors.WithStack(err)
		}
	} else {
		u.Name = user.Name
		u.ProviderUserid = user.UserID
		u.Provider = user.Provider
		u.GravatarID = nulls.NewString(user.AvatarURL)
	}
	u.Nickname = nulls.NewString(user.NickName)
	err = tx.Save(u)
	if err != nil {
		return errors.WithStack(err)
	}

	c.Session().Set("current_user_id", u.ID)
	err = c.Session().Save()
	if err != nil {
		errors.WithStack(err)
	}

	c.Flash().Add("success", "You have been successfully logged in")
	return c.Redirect(302, "/")
}

// AuthDestroy deletes the user's session
func AuthDestroy(c buffalo.Context) error {
	c.Session().Clear()
	err := c.Session().Save()
	if err != nil {
		errors.WithStack(err)
	}
	c.Flash().Add("success", "You have been successfully logged out!")
	return c.Redirect(302, "/")
}

// SetCurrentUser finds and sets the logged in user
func SetCurrentUser(next buffalo.Handler) buffalo.Handler {
	return func(c buffalo.Context) error {
		if uid := c.Session().Get("current_user_id"); uid != nil {
			u := &models.User{}
			tx := c.Value("tx").(*pop.Connection)
			err := tx.Find(u, uid)
			if err != nil {
				errors.WithStack(err)
			}
			c.Set("current_user", u)
			c.Set("current_user_id", u.ID)
		}
		return next(c)
	}
}

// Authorize makes sure a user is authorized to visit a page
func Authorize(next buffalo.Handler) buffalo.Handler {
	return func(c buffalo.Context) error {
		if uid := c.Session().Get("current_user_id"); uid == nil {
			c.Flash().Add("danger", "You must be authorized!, Please login")
			return c.Redirect(302, "/")
		}
		return next(c)
	}
}
