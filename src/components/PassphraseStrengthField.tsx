/**
 * A passphrase strength readout: the segmented `PasswordStrengthMeter` paired
 * with a minimum-length indicator, sharing the same i18n score labels and
 * length rule. Used by every wallet form that grades a new passphrase (adding
 * or changing one in Settings), so the meter labels and the length rule stay in
 * one place instead of being copied per form.
 */
import Typography from '@mui/material/Typography'
import { MdCheck, MdClose } from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import { PasswordStrengthMeter } from '@/components/PasswordStrengthMeter'
import { PASSWORD_RULES } from '@/app.config'

/**
 * Renders the strength meter plus the minimum-length rule for a passphrase.
 *
 * @param options {object}
 * @param options.password {string}   the passphrase being graded
 * @param options.onChangeScore {function}   called with the latest score (0-4)
 * @returns {JSX.Element}
 */
export function PassphraseStrengthField({
  password,
  onChangeScore
}: {
  password: string
  onChangeScore: (score: number) => void
}) {
  const { t } = useTranslation()
  const lengthPassed = password.length >= PASSWORD_RULES.minlength
  return (
    <>
      <PasswordStrengthMeter
        password={password}
        onChangeScore={onChangeScore}
        scoreWords={
          (t('auth.signup.passwordScores', {
            returnObjects: true
          }) as string[]) ?? ['Weak', 'Weak', 'Fair', 'Strong', 'Very strong']
        }
        shortScoreWord={t('auth.signup.passwordTooShort')}
      />
      <Typography
        variant="body2"
        color={lengthPassed ? 'success.main' : 'text.secondary'}
        sx={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 0.5
        }}
      >
        {lengthPassed ? <MdCheck aria-hidden /> : <MdClose aria-hidden />}{' '}
        {t('auth.signup.minChars', {
          count: PASSWORD_RULES.minlength
        })}
      </Typography>
    </>
  )
}
