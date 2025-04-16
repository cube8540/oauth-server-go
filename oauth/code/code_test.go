package code

import (
	"oauth-server-go/oauth/pkg"
	"testing"
)

func TestAuthorizationCode_Verifier(t *testing.T) {
	code := AuthorizationCode{}
	tests := []struct {
		name      string
		challenge pkg.Challenge
		method    pkg.ChallengeMethod
		verifier  pkg.Verifier
		except    bool
	}{
		{
			name:      "해싱 방식 PLAN/일치하지 않는 verifier",
			challenge: "IAouJo2w1U8DnurVA5dgfqP5WZ5KLCMdiaeY89ZNum2",
			method:    pkg.ChallengePlan,
			verifier:  "wrong verifier",
			except:    false,
		},
		{
			name:      "해싱 방식 PLAN/일치하는 verifier",
			challenge: "IAouJo2w1U8DnurVA5dgfqP5WZ5KLCMdiaeY89ZNum2",
			method:    pkg.ChallengePlan,
			verifier:  "IAouJo2w1U8DnurVA5dgfqP5WZ5KLCMdiaeY89ZNum2",
			except:    true,
		},
		{
			name:      "해싱 방식 S256/일치하지 않는 verifier",
			challenge: "efe_rqmpENryXVEZv63WKXAg4p6YJUiDJoZJBu8JuVE=",
			method:    pkg.ChallengeS256,
			verifier:  "wrong verifier",
			except:    false,
		},
		{
			name:      "해싱 방식 S256/일치하는 verifier",
			challenge: "efe_rqmpENryXVEZv63WKXAg4p6YJUiDJoZJBu8JuVE=",
			method:    pkg.ChallengeS256,
			verifier:  "IAouJo2w1U8DnurVA5dgfqP5WZ5KLCMdiaeY89ZNum2",
			except:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code.CodeChallenge = tc.challenge
			code.CodeChallengeMethod = tc.method

			r, _ := code.Verifier(tc.verifier)
			if r != tc.except {
				t.Errorf("반환되는 결과는 \"%t\"이어야 합니다", tc.except)
			}
		})
	}
}
