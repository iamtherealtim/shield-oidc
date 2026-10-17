<?php
/**
 * @var list<DaemonLabs\ShieldOidc\Provider> $providers
 * @var string|null                          $returnTo
 */
if ($providers === []) {
    return;
}
?>
<div class="oidc-buttons">
<?php foreach ($providers as $p): ?>
    <a class="oidc-button oidc-button-<?= esc($p->key, 'attr') ?> btn btn-outline-secondary" href="<?= esc(oidc_login_url($p->key, $returnTo), 'attr') ?>"><?= esc(lang('Oidc.signInWith', [$p->label])) ?></a>
<?php endforeach ?>
</div>
