defmodule TransportWeb.Live.NotificationsLiveSecurityTest do
  @moduledoc """
  Security regression tests for NotificationsLive (producer space).

  These tests assert that access control is enforced. They are expected to FAIL
  as long as the vulnerability is present: a user must not be able to create a
  `role: :producer` notification subscription on a dataset they do not produce,
  by forging the `phx-value-dataset-id` sent to the `toggle` LiveEvent.

  See `handle_event "toggle"` in `TransportWeb.Live.NotificationsLive`:
  the `toggle_subscription/5` "turn_on" clause inserts the subscription using
  the client-provided `dataset_id`, without checking that it belongs to
  `socket.assigns.datasets` (the datasets the user is a producer of).
  """
  use TransportWeb.ConnCase, async: true
  use TransportWeb.LiveCase
  use Oban.Testing, repo: DB.Repo

  import DB.Factory
  import Mox
  import Phoenix.LiveViewTest
  import Swoosh.TestAssertions

  alias Transport.Jobs.ExpirationNotificationJob

  @producer_url espace_producteur_path(TransportWeb.Endpoint, :notifications)

  setup :verify_on_exit!

  setup do
    Mox.stub_with(Transport.ValidatorsSelection.Mock, Transport.ValidatorsSelection.Impl)
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(DB.Repo)
  end

  describe "producer notification subscriptions must be scoped to datasets the user produces" do
    test "a user cannot subscribe (role :producer) to a dataset owned by another organization", %{conn: conn} do
      %DB.Dataset{id: victim_dataset_id} = victim_dataset = insert_victim_dataset()

      attacker = insert_attacker()

      # The producer notifications page needs the transport.data.gouv.fr admin contact
      insert_admin()

      # data.gouv.fr answers with the attacker's organizations only: the victim
      # dataset is legitimately NOT part of the attacker's datasets
      Datagouvfr.Client.User.Mock
      |> expect(:me, 2, fn _ -> {:ok, %{"organizations" => [%{"id" => attacker.organization_id}]}} end)

      {:ok, view, html} =
        conn
        |> init_test_session(%{current_user: %{"id" => attacker.datagouv_user_id}, datagouv_token: %{}})
        |> get(@producer_url)
        |> live()

      # Sanity check: the attacker's page does not list the victim dataset,
      # they are not one of its producers
      refute html =~ victim_dataset.custom_title

      # The attacker forges the `toggle` LiveEvent (phx-value-dataset-id) to
      # target the victim dataset, as any crafted LiveView client payload would do
      forge_producer_subscription(view, victim_dataset_id)

      # SECURITY: creating the subscription must be refused. The attacker is
      # not a producer of the victim dataset, so no DB.NotificationSubscription
      # should exist. This assertion fails while the vulnerability is present:
      # a `role: :producer` subscription is created for the attacker on the
      # victim's dataset.
      assert [] = DB.Repo.all(DB.NotificationSubscription),
             "a user must not be able to create a :producer notification subscription on a dataset they do not produce"
    end

    test "the expiration notification job must not email a non-producer who forged a subscription", %{conn: conn} do
      # A victim dataset with a GTFS resource expiring tomorrow
      %DB.Dataset{id: victim_dataset_id} = victim_dataset = insert_victim_dataset()

      %DB.Resource{id: resource_id} =
        resource = insert(:resource, dataset_id: victim_dataset_id, format: "GTFS", title: "Super GTFS")

      multi_validation =
        insert(:multi_validation,
          validator: Transport.Validators.GTFSTransport.validator_name(),
          resource_history: insert(:resource_history, resource: resource)
        )

      insert(:resource_metadata,
        multi_validation_id: multi_validation.id,
        metadata: %{"end_date" => Date.utc_today()}
      )

      # Sanity check: the dataset is picked up by the producer/admin expiration job
      assert [{%DB.Dataset{id: ^victim_dataset_id}, [%DB.Resource{id: ^resource_id}]}] =
               Date.utc_today() |> Transport.Expiration.datasets_with_resources_expiring_on()

      attacker = insert_attacker()
      insert_admin()

      Datagouvfr.Client.User.Mock
      |> expect(:me, 2, fn _ -> {:ok, %{"organizations" => [%{"id" => attacker.organization_id}]}} end)

      # The attacker is not a producer of the victim dataset: their page does
      # not list it
      {:ok, view, html} =
        conn
        |> init_test_session(%{current_user: %{"id" => attacker.datagouv_user_id}, datagouv_token: %{}})
        |> get(@producer_url)
        |> live()

      refute html =~ victim_dataset.custom_title

      # The attacker forges the `toggle` LiveEvent to subscribe as a producer
      forge_producer_subscription(view, victim_dataset_id)

      # The daily expiration job runs
      assert :ok == perform_job(ExpirationNotificationJob, %{}, inserted_at: DateTime.utc_now())

      # SECURITY: the producer expiration email is reserved to the producers of
      # the dataset: it must not be delivered to the attacker. This assertion
      # fails while the vulnerability is present: the job selects recipients
      # through DB.NotificationSubscription.subscriptions_for_reason_dataset_and_role/3
      # and sends the victim dataset's producer notification to the attacker.
      attacker_email = attacker.email
      refute_email_sent(%Swoosh.Email{to: [{_, ^attacker_email}]})

      # And no notification must be recorded for the attacker
      assert [] = DB.Repo.all(DB.Notification)
    end
  end

  # The victim is a producer organization, owning a dataset
  defp insert_victim_dataset do
    %DB.Organization{id: organization_id} = insert(:organization)

    insert(:dataset,
      custom_title: "JDD d'une autre organisation",
      organization_id: organization_id
    )
  end

  # The attacker is a regular authenticated user, member of a *different*
  # organization, producing no dataset at all
  defp insert_attacker do
    %DB.Organization{id: attacker_organization_id} = insert(:organization)

    %DB.Contact{datagouv_user_id: datagouv_user_id, email: email} =
      insert_contact(%{
        datagouv_user_id: Ecto.UUID.generate(),
        organizations: [%{id: attacker_organization_id}]
      })

    %{datagouv_user_id: datagouv_user_id, email: email, organization_id: attacker_organization_id}
  end

  defp forge_producer_subscription(view, dataset_id) do
    render_change(view, :toggle, %{
      "dataset-id" => dataset_id,
      "subscription-id" => "",
      "reason" => "expiration",
      "action" => "turn_on"
    })
  end

  defp insert_admin do
    insert_contact(%{
      organizations: [
        %{
          "name" => "Point d'Accès National transport.data.gouv.fr",
          "acronym" => nil,
          "badges" => [],
          "id" => Ecto.UUID.generate(),
          "logo" => "https://example.com/original.png",
          "logo_thumbnail" => "https://example.com/100.png",
          "slug" => "foo" <> Ecto.UUID.generate()
        }
      ]
    })
  end
end
