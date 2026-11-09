"""Use the same installation validator as CLI preflight."""

from certweaver.installation import container_model, verified_manifest_images


class FilterModule:
    def filters(self):
        return {
            "certweaver_container_model": container_model,
            "certweaver_verified_manifest_images": verified_manifest_images,
        }
