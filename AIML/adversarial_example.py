#!/usr/bin/env python3
"""
adversarial_example.py -- Generate a simple FGSM adversarial perturbation
against an image classifier, common in "fool the model" AI/ML CTF challenges.

Requires: pip install torch torchvision pillow numpy

Usage:
    python3 adversarial_example.py --image cat.png --target-class 999 --epsilon 0.03
    (defaults to using a pretrained torchvision ResNet18 as a stand-in --
     swap `load_model()` for the challenge's actual model if provided as a file)
"""
import argparse
import torch
import torch.nn.functional as F
from torchvision import models, transforms
from PIL import Image


def load_model(weights_path=None):
    if weights_path:
        model = torch.load(weights_path, map_location="cpu")
    else:
        model = models.resnet18(weights=models.ResNet18_Weights.DEFAULT)
    model.eval()
    return model


PREPROCESS = transforms.Compose([
    transforms.Resize(256),
    transforms.CenterCrop(224),
    transforms.ToTensor(),
])


def fgsm_attack(model, image_tensor, target_class, epsilon):
    """Targeted FGSM: nudges the image toward being classified as target_class."""
    image_tensor = image_tensor.clone().detach().requires_grad_(True)
    output = model(image_tensor.unsqueeze(0))
    loss = F.cross_entropy(output, torch.tensor([target_class]))
    model.zero_grad()
    loss.backward()

    # For targeted attack, step in the negative gradient direction (minimize loss for target)
    perturbation = -epsilon * image_tensor.grad.sign()
    adv_image = torch.clamp(image_tensor + perturbation, 0, 1)
    return adv_image.detach()


def pgd_attack(model, image_tensor, target_class, epsilon, alpha=0.005, steps=20):
    """Iterative version (PGD), generally more effective than single-step FGSM."""
    orig = image_tensor.clone().detach()
    adv = image_tensor.clone().detach()

    for _ in range(steps):
        adv.requires_grad_(True)
        output = model(adv.unsqueeze(0))
        loss = F.cross_entropy(output, torch.tensor([target_class]))
        model.zero_grad()
        loss.backward()

        adv = adv.detach() - alpha * adv.grad.sign()
        perturbation = torch.clamp(adv - orig, -epsilon, epsilon)
        adv = torch.clamp(orig + perturbation, 0, 1).detach()

    return adv


def predict(model, image_tensor):
    with torch.no_grad():
        output = model(image_tensor.unsqueeze(0))
        probs = F.softmax(output, dim=1)
        top_prob, top_class = probs.max(1)
    return top_class.item(), top_prob.item()


def main():
    ap = argparse.ArgumentParser(description="Adversarial example generator (FGSM/PGD)")
    ap.add_argument("--image", required=True)
    ap.add_argument("--target-class", type=int, required=True)
    ap.add_argument("--epsilon", type=float, default=0.03)
    ap.add_argument("--method", choices=["fgsm", "pgd"], default="pgd")
    ap.add_argument("--weights", help="path to a custom model .pt file, if given by the challenge")
    ap.add_argument("--out", default="adversarial_output.png")
    args = ap.parse_args()

    model = load_model(args.weights)
    img = Image.open(args.image).convert("RGB")
    tensor = PREPROCESS(img)

    orig_class, orig_conf = predict(model, tensor)
    print(f"[*] Original prediction: class={orig_class} confidence={orig_conf:.3f}")

    if args.method == "fgsm":
        adv = fgsm_attack(model, tensor, args.target_class, args.epsilon)
    else:
        adv = pgd_attack(model, tensor, args.target_class, args.epsilon)

    new_class, new_conf = predict(model, adv)
    print(f"[+] Adversarial prediction: class={new_class} confidence={new_conf:.3f}")

    adv_img = transforms.ToPILImage()(adv)
    adv_img.save(args.out)
    print(f"[+] Saved adversarial image to {args.out}")


if __name__ == "__main__":
    main()
