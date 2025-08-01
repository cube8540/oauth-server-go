package authorization

import (
	"testing"
)

func TestCode_Verifier(t *testing.T) {
	code := Code{}
	tests := []struct {
		name      string
		challenge Challenge
		method    ChallengeMethod
		verifier  Verifier
		except    bool
	}{
		{
			name:      "해싱 방식 PLAN/일치하지 않는 verifier",
			challenge: "IAouJo2w1U8DnurVA5dgfqP5WZ5KLCMdiaeY89ZNum2",
			method:    ChallengePlan,
			verifier:  "wrong verifier",
			except:    false,
		},
		{
			name:      "해싱 방식 PLAN/일치하는 verifier",
			challenge: "IAouJo2w1U8DnurVA5dgfqP5WZ5KLCMdiaeY89ZNum2",
			method:    ChallengePlan,
			verifier:  "IAouJo2w1U8DnurVA5dgfqP5WZ5KLCMdiaeY89ZNum2",
			except:    true,
		},
		{
			name:      "해싱 방식 S256/일치하지 않는 verifier",
			challenge: "efe_rqmpENryXVEZv63WKXAg4p6YJUiDJoZJBu8JuVE=",
			method:    ChallengeS256,
			verifier:  "wrong verifier",
			except:    false,
		},
		{
			name:      "해싱 방식 S256/일치하는 verifier",
			challenge: "efe_rqmpENryXVEZv63WKXAg4p6YJUiDJoZJBu8JuVE=",
			method:    ChallengeS256,
			verifier:  "IAouJo2w1U8DnurVA5dgfqP5WZ5KLCMdiaeY89ZNum2",
			except:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code.codeChallenge = tc.challenge
			code.codeChallengeMethod = tc.method

			result, _ := code.Verify(tc.verifier)
			if result != tc.except {
				t.Errorf("반환되는 결과는 \"%t\"이어야 합니다", tc.except)
			}
		})
	}
}
